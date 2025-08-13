/*
 * Test for the filter API
 * sudo iptables -A INPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
 */
/*
# Increase kernel connection tracking limits
echo 300000 > /proc/sys/net/netfilter/nf_conntrack_max
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=5400

# Increase socket buffers
sysctl -w net.core.rmem_max=4194304
sysctl -w net.core.rmem_default=2097152

# Protect against SYN floods
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_syncookies=1
*/

#include <ebpf_firewall_common.h>
#include <ebpf_firewall_conntrack.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_config.h>

#define MAX_EVENTS 10
#define MAX_RETRIES 3
#define RECOVERY_DELAY_US 1000                // 1ms
#define BUFFER_SIZE        (2 * 1024 * 1024)  // 2MB

static struct nfct_handle *h = NULL;
extern int exiting;
extern struct global_firewall_config global_fw_config;

static int ct_family = AF_INET;
static size_t current_buf_size = BUFFER_SIZE;
static int established_map_fd;
static int connection_map_fd;
static int block_ips_map_fd;

/* Get timestamp string */
static const char *get_timestamp() {
    static char buf[64];
    time_t now = time(NULL);
    struct tm *tinfo = localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tinfo);
    return buf;
}

/* Adjust socket receive buffer size, with force option */
static void set_socket_buffer_size(int fd, size_t size) {
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0) {
        LOG_E("setsockopt SO_RCVBUF %s\n", strerror(errno));
#ifdef SO_RCVBUFFORCE
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) < 0) {
            LOG_E("setsockopt SO_RCVBUFFORCE %s\n", strerror(errno));
        }
#endif
    }
}

/* Connection event callback */
static int event_cb(enum nf_conntrack_msg_type type,
                    struct nf_conntrack *ct,
                    void *data) {

    uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    if (proto != IPPROTO_TCP)
        return NFCT_CB_CONTINUE;

    uint8_t state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
    if ((type == NFCT_T_NEW || type == NFCT_T_UPDATE) && state != TCP_CONNTRACK_ESTABLISHED)
        return NFCT_CB_CONTINUE;

    uint32_t sip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
    uint32_t dip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
    uint16_t sport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
    uint16_t dport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
    
    /*struct in_addr in;
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    in.s_addr = sip;
    inet_ntop(AF_INET, &in, src_str, sizeof(src_str));
    in.s_addr = dip;
    inet_ntop(AF_INET, &in, dst_str, sizeof(dst_str));

    const char *type_str = (type == NFCT_T_DESTROY) ? "Destroyed" :
        (type == NFCT_T_NEW ? "New      " : "Updated  ");

    LOG_I("%s TCP %s:%u -> %s:%u (State: %d)\n",
          type_str,
          src_str, ntohs(sport),
          dst_str, ntohs(dport),
          state);*/
    
    // TCP established map check for ACK flooding
    __u64 key = sport;
    key = ((key << 32) | sip);
    __u8 value = 1;

    if (type == NFCT_T_UPDATE) {
        if (bpf_map_update_elem(established_map_fd, &key, &value, BPF_ANY)) {
            LOG_E( "Failed to update tcp_established_session map_id (%d): %s\n", established_map_fd, strerror(errno));
        }
    }

    if (type == NFCT_T_DESTROY) {
        bpf_map_delete_elem(established_map_fd, &key);
    }

    // TCP connection limit check
    if (global_fw_config.g_tcp_connection_config.check != 0) {
        struct in_addr in;
        char src_str[INET_ADDRSTRLEN];
        in.s_addr = sip;
        inet_ntop(AF_INET, &in, src_str, sizeof(src_str));

        __u32 con_count = 0;
        //if (bpf_map_lookup_elem(connection_map_fd, &sip, &con_count) == 0) {
        //    LOG_D("Connection count [%s] is %d\n", src_str, con_count);
        //}

        if (type == NFCT_T_UPDATE)
            con_count ++;
        if (type == NFCT_T_DESTROY && con_count > 0)
            con_count --;
        if (bpf_map_update_elem(connection_map_fd, &sip, &con_count, BPF_ANY) != 0) {
            LOG_E("Failed to update connection_map_fd BPF map : %s\n", strerror(errno));
        }

        if (con_count >= global_fw_config.g_tcp_connection_config.limit_cnt) {
            LOG_C("TCP connection reaches to limit [%s] -> %d\n", src_str, con_count);

            // Add source ip to block list
            // now = bpf_ktime_get_ns()
            
            struct timespec ts;
            // CLOCK_MONOTONIC gives monotonic time since some unspecified starting point
            if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
                LOG_E("clock_gettime failed : %s", strerror(errno));
            } else {
                __u64 now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
                __u64 expire = now + global_fw_config.g_config.black_ip_duration;
                bpf_map_update_elem(block_ips_map_fd, &sip, &expire, BPF_ANY);
            }
        }
    }

    return NFCT_CB_CONTINUE;
}

/* Thread to monitor conntrack events */
static void *conntrack_thread(void *arg) {
    struct nfct_handle *handle = (struct nfct_handle *)arg;
    int epoll_fd, nfctfd;
    struct epoll_event ev, events[MAX_EVENTS];

    nfctfd = nfct_fd(handle);

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        LOG_E("epoll_create1 %s\n", strerror(errno));
        return NULL;
    }
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ev.data.fd = nfctfd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, nfctfd, &ev) < 0) {
        LOG_E("epoll_ctl %s\n", strerror(errno));
        close(epoll_fd);
        return NULL;
    }

    while (!exiting) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOG_E("epoll_wait %s\n", strerror(errno));
            break;
        }
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == nfctfd) {
                int ret = nfct_catch(handle);
                if (ret < 0 && errno == ENOBUFS) {
                    LOG_W("Conntrack buffer overflow, recovering...\n");
                    usleep(RECOVERY_DELAY_US);
                    current_buf_size *= 2;
                    set_socket_buffer_size(nfctfd, current_buf_size);
                    if (nfct_query(handle, NFCT_Q_DUMP, &ct_family) < 0) {
                        LOG_E("Recovery dump failed: %s\n",
                                strerror(errno));
                    } else {
                        LOG_D("Recovery sync successful\n");
                    }
                    continue;
                } else if (ret < 0) {
                    LOG_E("nfct_catch: %s\n", strerror(errno));
                    exiting = 1;
                    break;
                }
            }
        }
    }

    close(epoll_fd);
    return NULL;
}

int init_conntrack(int tcp_established_fd, int tcp_connection_fd, int block_ips_fd) {
    pthread_t ct_thread;

    LOG_D("Initializing conntrack map(%d,%d,%d)\n", tcp_established_fd, tcp_connection_fd, block_ips_fd);

    h = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
    if (!h) {
        LOG_E("nfct_open %s\n", strerror(errno));
        return -1;
    }

    set_socket_buffer_size(nfct_fd(h), current_buf_size);
    established_map_fd = tcp_established_fd;
    connection_map_fd = tcp_connection_fd;
    block_ips_map_fd = block_ips_fd;
    
    if (nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL) < 0) {
        LOG_E("nfct_callback_register %s\n", strerror(errno));
        nfct_close(h);
        return -1;
    }

    LOG_D("Loading existing connections...\n");
    int retry = 0;
    while (retry < MAX_RETRIES) {
        if (nfct_query(h, NFCT_Q_DUMP, &ct_family) < 0) {
            if (errno == ENOBUFS) {
                LOG_W("WARNING: Initial dump buffer overflow (attempt %d/%d)\n", retry+1, MAX_RETRIES);
                retry++;
                usleep(RECOVERY_DELAY_US);
                current_buf_size *= 2;
                set_socket_buffer_size(nfct_fd(h), current_buf_size);
                continue;
            }
            LOG_E("nfct_query %s\n", strerror(errno));
            nfct_close(h);
            return -1;
        }
        break;
    }

    LOG_D("Now monitoring connections...\n");

    if (pthread_create(&ct_thread, NULL, conntrack_thread, h) != 0) {
        LOG_E("pthread_create %s\n", strerror(errno));
        nfct_close(h);
        return -1;
    }

    return 0;
}

void close_conntrack() {
    if (h) nfct_close(h);
}