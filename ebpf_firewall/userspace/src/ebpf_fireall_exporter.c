// ebpf_firewall_exporter.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <microhttpd.h>
#include <prom.h>
#include <promhttp.h>

#define LISTEN_PORT 9115
#define CLI_CMD     "./ebpf_firewall_cli STATS_FW"

// Gauges for each protocol: received & passed
static prom_gauge_t *g_SYN_recv,    *g_SYN_pass;
static prom_gauge_t *g_ACK_recv,    *g_ACK_pass;
static prom_gauge_t *g_RST_recv,    *g_RST_pass;
static prom_gauge_t *g_PSH_recv,    *g_PSH_pass;
static prom_gauge_t *g_FIN_recv,    *g_FIN_pass;
static prom_gauge_t *g_URG_recv,    *g_URG_pass;
static prom_gauge_t *g_SYN_ACK_recv, *g_SYN_ACK_pass;
static prom_gauge_t *g_FIN_ACK_recv, *g_FIN_ACK_pass;
static prom_gauge_t *g_RST_ACK_recv, *g_RST_ACK_pass;
static prom_gauge_t *g_ICMP_recv,   *g_ICMP_pass;
static prom_gauge_t *g_UDP_recv,    *g_UDP_pass;
static prom_gauge_t *g_GRE_recv,    *g_GRE_pass;


static prom_gauge_t *g_PKT_SYN_normal,    *g_PKT_SYN_attack;
static prom_gauge_t *g_PKT_ACK_normal,    *g_PKT_ACK_attack;
static prom_gauge_t *g_PKT_RST_normal,    *g_PKT_RST_attack;
static prom_gauge_t *g_PKT_PSH_normal,    *g_PKT_PSH_attack;
static prom_gauge_t *g_PKT_FIN_normal,    *g_PKT_FIN_attack;
static prom_gauge_t *g_PKT_URG_normal,    *g_PKT_URG_attack;
static prom_gauge_t *g_PKT_SYN_ACK_normal,    *g_PKT_SYN_ACK_attack;
static prom_gauge_t *g_PKT_FIN_ACK_normal,    *g_PKT_FIN_ACK_attack;
static prom_gauge_t *g_PKT_RST_ACK_normal,    *g_PKT_RST_ACK_attack;
static prom_gauge_t *g_PKT_ICMP_normal,    *g_PKT_ICMP_attack;
static prom_gauge_t *g_PKT_UDP_normal,    *g_PKT_UDP_attack;
static prom_gauge_t *g_PKT_GRE_normal,    *g_PKT_GRE_attack;

static volatile int keep_running = 1;
static struct MHD_Daemon *httpd = NULL;

static void int_handler(int sig) {
    keep_running = 0;
}

static void register_metrics(void) {
    // 1) Initialize the default registry & process collector
    prom_collector_registry_default_init();

    // 2) Create & register each gauge
    #define NEW_METRIC(NAME)                                                        \
      do {                                                                          \
        g_##NAME##_recv = prom_gauge_new(                                           \
          "ebpf_fw_" #NAME "_received_total",                                       \
          "Total " #NAME " packets received", 0, NULL                                \
        );                                                                          \
        prom_collector_registry_must_register_metric((prom_metric_t*)g_##NAME##_recv);\
                                                                                   \
        g_##NAME##_pass = prom_gauge_new(                                           \
          "ebpf_fw_" #NAME "_passed_total",                                         \
          "Total " #NAME " packets passed",   0, NULL                                \
        );                                                                          \
        prom_collector_registry_must_register_metric((prom_metric_t*)g_##NAME##_pass);\
      } while(0)

    NEW_METRIC(SYN);
    NEW_METRIC(ACK);
    NEW_METRIC(RST);
    NEW_METRIC(PSH);
    NEW_METRIC(FIN);
    NEW_METRIC(URG);
    NEW_METRIC(SYN_ACK);
    NEW_METRIC(FIN_ACK);
    NEW_METRIC(RST_ACK);
    NEW_METRIC(ICMP);
    NEW_METRIC(UDP);
    NEW_METRIC(GRE);

    #define NEW_PKT_METRIC(NAME)                                                        \
      do {                                                                          \
        g_##NAME##_normal = prom_gauge_new(                                           \
          "ebpf_fw_" #NAME "_pkt_normal",                                       \
          "MAX " #NAME " packets per IP in normal", 0, NULL                                \
        );                                                                          \
        prom_collector_registry_must_register_metric((prom_metric_t*)g_##NAME##_normal);\
                                                                                   \
        g_##NAME##_attack = prom_gauge_new(                                           \
          "ebpf_fw_" #NAME "_pkt_attack",                                         \
          "MAX " #NAME " packets per IP in attack",   0, NULL                                \
        );                                                                          \
        prom_collector_registry_must_register_metric((prom_metric_t*)g_##NAME##_attack);\
      } while(0)
    
    NEW_PKT_METRIC(PKT_SYN);
    NEW_PKT_METRIC(PKT_ACK);
    NEW_PKT_METRIC(PKT_RST);
    NEW_PKT_METRIC(PKT_PSH);
    NEW_PKT_METRIC(PKT_FIN);
    NEW_PKT_METRIC(PKT_URG);
    NEW_PKT_METRIC(PKT_SYN_ACK);
    NEW_PKT_METRIC(PKT_FIN_ACK);
    NEW_PKT_METRIC(PKT_RST_ACK);
    NEW_PKT_METRIC(PKT_ICMP);
    NEW_PKT_METRIC(PKT_UDP);
    NEW_PKT_METRIC(PKT_GRE);
}

static void fetch_and_update_metrics(void) {
    FILE *fp = popen(CLI_CMD, "r");
    if (!fp) return;

    char buf[512];
    if (fgets(buf, sizeof(buf), fp)) {
        // e.g. "OK SYN:1/1 ACK:5/5 …"
        char *token = strtok(buf, " \n");
        while (token) {
            if (strcmp(token, "OK") != 0) {
                char proto[32];
                int recv, pass;
                if (sscanf(token, "%31[^:]:%d/%d", proto, &recv, &pass) == 3) {
                    #define SET_METRIC(NAME)                                     \
                      if (strcmp(proto, #NAME) == 0) {                         \
                        prom_gauge_set(g_##NAME##_recv, recv,  NULL); /* recv */ \
                        prom_gauge_set(g_##NAME##_pass, pass,  NULL); /* pass */ \
                      }

                    SET_METRIC(SYN);
                    SET_METRIC(ACK);
                    SET_METRIC(RST);
                    SET_METRIC(PSH);
                    SET_METRIC(FIN);
                    SET_METRIC(URG);
                    SET_METRIC(SYN_ACK);
                    SET_METRIC(FIN_ACK);
                    SET_METRIC(RST_ACK);
                    SET_METRIC(ICMP);
                    SET_METRIC(UDP);
                    SET_METRIC(GRE);

                    #define SET_PKT_METRIC(NAME)                                     \
                      if (strcmp(proto, #NAME) == 0) {                         \
                        prom_gauge_set(g_##NAME##_normal, recv,  NULL); /* normal */ \
                        prom_gauge_set(g_##NAME##_attack, pass,  NULL); /* attack */ \
                      }
                    
                    SET_PKT_METRIC(PKT_SYN);
                    SET_PKT_METRIC(PKT_ACK);
                    SET_PKT_METRIC(PKT_RST);
                    SET_PKT_METRIC(PKT_PSH);
                    SET_PKT_METRIC(PKT_FIN);
                    SET_PKT_METRIC(PKT_URG);
                    SET_PKT_METRIC(PKT_SYN_ACK);
                    SET_PKT_METRIC(PKT_FIN_ACK);
                    SET_PKT_METRIC(PKT_RST_ACK);
                    SET_PKT_METRIC(PKT_ICMP);
                    SET_PKT_METRIC(PKT_UDP);
                    SET_PKT_METRIC(PKT_GRE);
                }
            }
            token = strtok(NULL, " \n");
        }
    }
    pclose(fp);
}

int main(void) {
    signal(SIGINT,  int_handler);
    signal(SIGTERM, int_handler);

    register_metrics();

    // Tell promhttp which registry to serve
    promhttp_set_active_collector_registry(PROM_COLLECTOR_REGISTRY_DEFAULT);

    // Start the HTTP server on LISTEN_PORT
    httpd = promhttp_start_daemon(
      MHD_USE_SELECT_INTERNALLY,
      LISTEN_PORT,
      /*accept_policy=*/ NULL,
      /*accept_cls=*/   NULL
    );
    if (!httpd) {
        fprintf(stderr, "Failed to start HTTP server on port %d\n", LISTEN_PORT);
        return 1;
    }
    printf("Exporter listening on :%d/metrics\n", LISTEN_PORT);

    // Update metrics every second
    while (keep_running) {
        fetch_and_update_metrics();
        sleep(1);
    }

    MHD_stop_daemon(httpd);
    return 0;
}
