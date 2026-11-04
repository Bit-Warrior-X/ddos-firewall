#define _GNU_SOURCE /* accept4 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ebpf_firewall_common.h>
#include <ebpf_firewall_nginx.h>
#include <ebpf_firewall_core.h>
#include <ebpf_firewall_log.h>

extern volatile sig_atomic_t exiting;

#define BUFFER_SIZE 1024

/* Change these as needed */
#ifndef NGINX_TCP_PORT
#define NGINX_TCP_PORT 9090
#endif

#ifndef NGINX_BIND_ADDR
#define NGINX_BIND_ADDR "127.0.0.1"
#endif

int sockfd = -1; /* listener socket fd */

/* One "block:<ip> [seconds]" message. */
static void handle_nginx_line(const char *line)
{
    if (strncmp(line, "block:", 6) != 0)
        return;
    char ip[64];
    int block_duration = 0;
    if (sscanf(line, "block:%63s %d", ip, &block_duration) < 1)
        return;
    LOG_N("NGINX send %s to add block list (duration parsed %d)\n", ip, block_duration);
    if (add_block_ip(ip, block_duration) >= 0)
        append_block_ip_to_sqlite(ip, block_duration,
            "Attacking in unregistered http request method");
}

/* per-client handler: newline-framed messages until the client closes.
 * A message split across reads (or several in one read) used to be
 * mis-parsed, blocking the wrong IP or dropping messages. */
#define NGINX_MAX_CLIENTS 64
static int active_clients;

static void *tcp_client_handler(void *arg)
{
    int client_fd = (int)(intptr_t)arg;
    char buffer[BUFFER_SIZE];
    size_t used = 0;

    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    while (!exiting) {
        ssize_t num_bytes = recv(client_fd, buffer + used, BUFFER_SIZE - 1 - used, 0);
        if (num_bytes < 0) {
            if (errno == EINTR)
                continue;
            LOG_E("recv on client_fd %d: %s\n", client_fd, strerror(errno));
            break;
        } else if (num_bytes == 0) {
            LOG_D("Client fd %d closed connection\n", client_fd);
            break;
        }
        used += (size_t)num_bytes;
        buffer[used] = '\0';

        char *line = buffer, *nl;
        while ((nl = strchr(line, '\n')) != NULL) {
            *nl = '\0';
            if (nl > line && nl[-1] == '\r')
                nl[-1] = '\0';
            handle_nginx_line(line);
            line = nl + 1;
        }
        used = strlen(line);
        memmove(buffer, line, used + 1);
        if (used >= BUFFER_SIZE - 1) {
            LOG_W("nginx client fd %d: message too long, dropped\n", client_fd);
            used = 0;
        }
    }
    /* Last message without a trailing newline (sender closed after writing). */
    if (used > 0) {
        buffer[used] = '\0';
        handle_nginx_line(buffer);
    }

    close(client_fd);
    __sync_fetch_and_sub(&active_clients, 1);
    return NULL;
}

/* listener/acceptor thread */
static void *tcp_acceptor(void *arg)
{
    (void)arg;
    while (!exiting) {
        /* Backpressure instead of one thread per connection without bound:
         * further connections wait in the listen backlog. */
        if (__atomic_load_n(&active_clients, __ATOMIC_ACQUIRE) >= NGINX_MAX_CLIENTS) {
            usleep(10 * 1000);
            continue;
        }
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd = accept4(sockfd, (struct sockaddr *)&cli_addr, &cli_len, SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            LOG_E("accept failed: %s\n", strerror(errno));
            usleep(100 * 1000);
            continue;
        }

        char peer_addr[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &cli_addr.sin_addr, peer_addr, sizeof(peer_addr));
        LOG_D("Accepted connection from %s:%d, fd=%d\n",
              peer_addr, ntohs(cli_addr.sin_port), client_fd);

        /* make client socket non-blocking optional (we keep blocking reads for simplicity) */
        /* set socket options if desired here */

        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        __sync_fetch_and_add(&active_clients, 1);
        if (pthread_create(&th, &attr, tcp_client_handler, (void *)(intptr_t)client_fd) != 0) {
            LOG_E("pthread_create for client handler failed\n");
            __sync_fetch_and_sub(&active_clients, 1);
            close(client_fd);
        }
        pthread_attr_destroy(&attr);
    }
    return NULL;
}

/* Initialize IPv4 TCP server listening on NGINX_BIND_ADDR:NGINX_TCP_PORT */
int init_nginx_socket(void) {
    struct sockaddr_in srv_addr;
    int opt = 1;

    sockfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sockfd < 0) {
        LOG_E("socket: %s\n", strerror(errno));
        return -1;
    }

    /* Allow quick restart */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_E("setsockopt SO_REUSEADDR failed: %s\n", strerror(errno));
        /* non-fatal */
    }

    int rcvbuf_size = 256 * 1024;  // 256KB
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
        LOG_E("setsockopt SO_RCVBUF failed: %s\n", strerror(errno));
    }

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(NGINX_TCP_PORT);
    if (inet_pton(AF_INET, NGINX_BIND_ADDR, &srv_addr.sin_addr) != 1) {
        LOG_E("inet_pton failed for address %s\n", NGINX_BIND_ADDR);
        close(sockfd);
        sockfd = -1;
        return -1;
    }

    if (bind(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        LOG_E("bind %s:%d failed: %s\n", NGINX_BIND_ADDR, NGINX_TCP_PORT, strerror(errno));
        close(sockfd);
        sockfd = -1;
        return -1;
    }

    if (listen(sockfd, SOMAXCONN) < 0) {
        LOG_E("listen failed: %s\n", strerror(errno));
        close(sockfd);
        sockfd = -1;
        return -1;
    }

    LOG_D("TCP server listening on %s:%d\n", NGINX_BIND_ADDR, NGINX_TCP_PORT);

    pthread_t acceptor_thr;
    if (pthread_create(&acceptor_thr, NULL, tcp_acceptor, NULL) != 0) {
        LOG_E("pthread_create for tcp_acceptor failed\n");
        close(sockfd);
        sockfd = -1;
        return -1;
    }

    /* we could detach or keep handle; acceptor runs until exiting */
    return 0;
}

void close_nginx_socket(void) {
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
}