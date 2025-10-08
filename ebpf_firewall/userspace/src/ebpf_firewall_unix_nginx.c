
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include <ebpf_firewall_common.h>
#include <ebpf_firewall_unix.h>
#include <ebpf_firewall_core.h>
#include <ebpf_firewall_log.h>

extern int exiting;

#define BUFFER_SIZE 1024

int sockfd;
static void * unix_socket_worker(void * arg)
{
    while (!exiting) {
        socklen_t cli_addr_len;
        ssize_t num_bytes;
        struct sockaddr_un cli_addr;

        char buffer[BUFFER_SIZE];
        cli_addr_len = sizeof(struct sockaddr_un);
        num_bytes = recvfrom(sockfd,
                             buffer,
                             BUFFER_SIZE - 1,
                             0,
                             (struct sockaddr *)&cli_addr,
                             &cli_addr_len);
        if (num_bytes < 0) {
            // If interrupted by signal, continue
            if (errno == EINTR)
                continue;
            LOG_E("recvfrom\n");
            break;
        }
        buffer[num_bytes] = '\0';  // Null‐terminate
        /*printf("Received %zd bytes from client [%s]: \"%s\"\n",
               num_bytes,
               cli_addr.sun_path[0] ? cli_addr.sun_path : "(anonymous)",
               buffer);*/

        if (num_bytes >= 4 && strncmp(buffer, "ping", 4) == 0) {
            // Ping packet is received
        }
        if (num_bytes >= 4 && strncmp(buffer, "block:", 6) == 0) {
            char ip[64];
            int block_duration = 0;
            if (sscanf(buffer, "block:%63s %d", ip, &block_duration) == 2) {
                LOG_N("NGINX send %s to add block list for %d seconds\n", ip, block_duration);
                add_block_ip(buffer + 6, 0);
                append_block_ip_to_sqlite(buffer + 6, "Attacking in unkown http request method");
            }
        }
    }

    return NULL;
}

int init_unix_nginx_socket(void) {
    struct sockaddr_un srv_addr, cli_addr;
    
    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOG_E("socket\n");
        return -1;
    }

    unlink(NGINX_UNIX_PATH);

    memset(&srv_addr, 0, sizeof(struct sockaddr_un));
    srv_addr.sun_family = AF_UNIX;
    strncpy(srv_addr.sun_path, NGINX_UNIX_PATH, sizeof(srv_addr.sun_path) - 1);

    if (bind(sockfd, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_un)) < 0) {
        LOG_E("bind\n");
        close(sockfd);
        return -1;
    }

    LOG_D("Unix‐domain DGRAM server listening at \"%s\"\n", NGINX_UNIX_PATH);

    pthread_t unix_socket_worker_thr;
    if (pthread_create(&unix_socket_worker_thr, NULL, unix_socket_worker, NULL) != 0) {
        LOG_E("pthread_create for unix_socket_worker_thr");
        return -1;
    }

    // Cleanup (unreachable here, but good practice)
    
}

void close_unix_nginx_socket(void) {
    close(sockfd);
    unlink(NGINX_UNIX_PATH);
}
