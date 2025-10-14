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

extern int exiting;

#define BUFFER_SIZE 1024

/* Change these as needed */
#ifndef NGINX_TCP_PORT
#define NGINX_TCP_PORT 9090
#endif

#ifndef NGINX_BIND_ADDR
#define NGINX_BIND_ADDR "127.0.0.1"
#endif

int sockfd; /* listener socket fd */

/* per-client handler: reads until client closes or exiting */
static void *tcp_client_handler(void *arg)
{
    int client_fd = (int)(intptr_t)arg;
    char buffer[BUFFER_SIZE];

    while (!exiting) {
        ssize_t num_bytes = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (num_bytes < 0) {
            if (errno == EINTR)
                continue;
            LOG_E("recv on client_fd %d: %s\n", client_fd, strerror(errno));
            break;
        } else if (num_bytes == 0) {
            /* client closed connection */
            LOG_D("Client fd %d closed connection\n", client_fd);
            break;
        }

        buffer[num_bytes] = '\0';
        LOG_D("Received %zd bytes from client fd %d: \"%s\"\n",
               num_bytes, client_fd, buffer);
#if 0
        if (num_bytes >= 4 && strncmp(buffer, "ping", 4) == 0) {
            ssize_t sent = send(client_fd, "pong", 4, 0);
            if (sent < 0) {
                LOG_E("Failed to send pong response to fd %d: %s\n",
                      client_fd, strerror(errno));
            } else {
                LOG_D("Sent pong response to health check (fd %d)\n", client_fd);
            }
            /* continue reading further messages from same connection */
            continue;
        }
#endif

        if (num_bytes >= 6 && strncmp(buffer, "block:", 6) == 0) {
            char ip[64];
            int block_duration = 0;
            /* try to parse "block:<ip> <duration>" */
            if (sscanf(buffer, "block:%63s %d", ip, &block_duration) >= 1) {
                LOG_N("NGINX send %s to add block list (duration parsed %d)\n",
                      ip, block_duration);
                // ip + duration is received. ex : 192.12.45.23 300

                add_block_ip(ip, block_duration);
                append_block_ip_to_sqlite(ip, block_duration, 
                    "Attacking in unregistered http request method");
            }
            continue;
        }

        /* If you want to echo or otherwise respond, add here */
    }

    close(client_fd);
    return NULL;
}

/* listener/acceptor thread */
static void *tcp_acceptor(void *arg)
{
    (void)arg;
    while (!exiting) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd = accept(sockfd, (struct sockaddr *)&cli_addr, &cli_len);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            LOG_E("accept failed: %s\n", strerror(errno));
            break;
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
        if (pthread_create(&th, &attr, tcp_client_handler, (void *)(intptr_t)client_fd) != 0) {
            LOG_E("pthread_create for client handler failed\n");
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

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
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
        return -1;
    }

    if (bind(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        LOG_E("bind %s:%d failed: %s\n", NGINX_BIND_ADDR, NGINX_TCP_PORT, strerror(errno));
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, SOMAXCONN) < 0) {
        LOG_E("listen failed: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    LOG_D("TCP server listening on %s:%d\n", NGINX_BIND_ADDR, NGINX_TCP_PORT);

    pthread_t acceptor_thr;
    if (pthread_create(&acceptor_thr, NULL, tcp_acceptor, NULL) != 0) {
        LOG_E("pthread_create for tcp_acceptor failed\n");
        close(sockfd);
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