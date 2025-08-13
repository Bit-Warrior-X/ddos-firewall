#ifndef EBPF_FIREWALL_CORE_H
#define EBPF_FIREWALL_CORE_H

int clear_batch_map(int map_fd);
int clear_geoip_trie_map(int map_fd);
int restart_fw();
int reload_fw();
int clear_fw();
int stats_fw(struct stats_config * stats);
int list_block_ip(char **out);
int get_block_list_ips(char **out, char *filter_type, char *filter_ip, char * date);
int clear_deny_ip(char * ip);
int clear_deny_ip_all();
int add_block_ip(char *ip, int seconds);
int list_allow_ip(char **out);
int clear_allow_ip(char * ip);
int clear_allow_ip_all();
int add_allow_ip(char *ip);

int tcp_syn_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration,
                int challenge_timeout);

int tcp_ack_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration);

int tcp_rst_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration);                

int icmp_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration);                               

int udp_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration);                               

int gre_set(int valid, 
                int threshold,
                int burst_pkt,
                int burst_counter,
                int fixed_threshold,
                int fixed_duration);
                
int tcp_seg_set(int valid);

int geo_set(int valid, 
            char * countries);

int tcp_conn_limit_set(int valid, 
            int count);            

int send_message_to_api_parser(const char *message);
int append_block_ip_to_sqlite(const char *ip_str, const char *reason); 
#endif