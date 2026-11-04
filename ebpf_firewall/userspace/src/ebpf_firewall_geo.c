#include <ebpf_firewall_common.h>
#include <ebpf_firewall_unix.h>
#include <ebpf_firewall_core.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_geo.h>
#include <pthread.h>

#define MAX_LINE 1024

static int load_locations(const char *path,
                          char iso_filters[][3], int n_filters,
                          uint32_t **out_gids, size_t *out_n) {
    FILE *f = fopen(path, "r");
    if (!f) { LOG_E("Failed to read location.csv "); return -1; }

    char line[MAX_LINE];
    // skip header
    fgets(line, sizeof line, f);

    uint32_t *gids = NULL;
    size_t    ng  = 0;

    while (fgets(line, sizeof line, f)) {
        // geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union
        char *save = NULL;
        char *tok = strtok_r(line, ",", &save);
        if (!tok) continue;
        uint32_t gid = atoi(tok);

        // skip to 5th field
        for (int i = 0; i < 4 && tok; i++) tok = strtok_r(NULL, ",", &save);
        if (!tok || strlen(tok) < 2) continue;

        // compare iso against filters
        for (int i = 0; i < n_filters; i++) {
            if (strcasecmp(tok, iso_filters[i]) == 0) {
                uint32_t *grown = realloc(gids, (ng+1)*sizeof *gids);
                if (!grown) {
                    free(gids);
                    fclose(f);
                    LOG_E("Out of memory loading location.csv\n");
                    return -1;
                }
                gids = grown;
                gids[ng++] = gid;
                break;
            }
        }
    }
    fclose(f);
    *out_gids = gids;
    *out_n    = ng;
    return 0;
}


static int load_ipv4(const char *path,
                     uint32_t *gids, size_t ng,
                     int map_fd, __u8 tag) {
    FILE *f = fopen(path, "r");
    if (!f) { LOG_E("Failed to read ipv4.csv"); return -1; }

    char line[MAX_LINE];
    // skip header
    fgets(line, sizeof line, f);

    while (fgets(line, sizeof line, f)) {
        char *save = NULL;
        char *cidr = strtok_r(line, ",", &save);
        char *gid_s = strtok_r(NULL, ",", &save);
        if (!cidr || !gid_s || *gid_s=='\0') continue;

        uint32_t gid = atoi(gid_s);
        // see if this gid is in our filter list
        int matched = 0;
        for (size_t i = 0; i < ng; i++) {
            if (gids[i] == gid) { matched = 1; break; }
        }
        if (!matched) continue;

        // parse network/prefix
        char *slash = strchr(cidr, '/');
        if (!slash)
            continue;
        *slash = 0;
        int prefix = atoi(slash+1);
        if (prefix < 0 || prefix > 32)
            continue;

        struct in_addr a;
        if (inet_pton(AF_INET, cidr, &a) != 1)
            continue;
        uint32_t net = a.s_addr;  // keep **network** byte order

        // populate LPM key
        struct lpm_key key = {
            .prefixlen = prefix,
            .ip        = net,
        };
        /* Any non-zero value matches in the kernel; the tag marks this rebuild. */
        __u8 val = tag;

        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0) {
            LOG_E("map_update failed: %s\n", strerror(errno));
        }
    }

    fclose(f);
    return 0;
}

static int init_geo_tagged(char * loc_path,
                           char * ipv4_path,
                           char   isos[][3], int nisos,
                           int map_fd, __u8 tag)
{
    uint32_t *gids = NULL;
    size_t    ng   = 0;

    LOG_D("Init Geo database\n");
    LOG_D("Database path is %s, %s\n", loc_path, ipv4_path);

    for (int i = 0 ; i < nisos ; i ++){
        LOG_D("Country iso is %s\n", isos[i]);
    }

    if (load_locations(loc_path, isos, nisos, &gids, &ng) < 0) {
        LOG_E("ERROR: loading GEO Location CSV data\n");
        return -1;
    }
    
    if (load_ipv4(ipv4_path, gids, ng, map_fd, tag) < 0) {
        LOG_E("ERROR: loading GEO ipv4 CSV data\n");
        free(gids);
        return -1;
    }

    if (gids) free(gids);

    return 0;
}

int init_geo(char * loc_path, 
             char * ipv4_path, 
             char   isos[][3], int nisos, 
             int map_fd)
{
    return init_geo_tagged(loc_path, ipv4_path, isos, nisos, map_fd, 1);
}

/* Delete entries whose tag equals (drop_tag_match) or differs from tag. */
static int prune_geo_map(int map_fd, __u8 tag, int drop_tag_match)
{
    struct lpm_key key, next;
    struct lpm_key *victims = NULL;
    size_t n = 0, cap = 0;
    int has = bpf_map_get_next_key(map_fd, NULL, &next) == 0;

    while (has) {
        __u8 val = 0;
        key = next;
        if (bpf_map_lookup_elem(map_fd, &key, &val) == 0 &&
            ((val == tag) == (drop_tag_match != 0))) {
            if (n == cap) {
                size_t ncap = cap ? cap * 2 : 1024;
                struct lpm_key *grown = realloc(victims, ncap * sizeof(*victims));
                if (!grown) {
                    free(victims);
                    LOG_E("Out of memory pruning geo map\n");
                    return -1;
                }
                victims = grown;
                cap = ncap;
            }
            victims[n++] = key;
        }
        has = bpf_map_get_next_key(map_fd, &key, &next) == 0;
    }
    for (size_t i = 0; i < n; i++)
        bpf_map_delete_elem(map_fd, &victims[i]);
    free(victims);
    LOG_D("Pruned %zu geo trie entries\n", n);
    return 0;
}

static pthread_mutex_t geo_lock = PTHREAD_MUTEX_INITIALIZER;
static __u8 geo_tag;

/*
 * Replace the trie contents without an empty window: the new set is inserted
 * under a fresh tag first, then entries with any other tag are deleted. While
 * loading, lookups see the old and new sets combined. On failure the partial
 * new set is removed and the previous one stays in place.
 */
int rebuild_geo_map(char * loc_path,
                    char * ipv4_path,
                    char   isos[][3], int nisos,
                    int map_fd)
{
    int rc;

    pthread_mutex_lock(&geo_lock);
    geo_tag = (__u8)(geo_tag % 255 + 1);
    __u8 tag = geo_tag;
    rc = init_geo_tagged(loc_path, ipv4_path, isos, nisos, map_fd, tag);
    if (rc < 0)
        prune_geo_map(map_fd, tag, 1);
    else
        rc = prune_geo_map(map_fd, tag, 0);
    pthread_mutex_unlock(&geo_lock);
    return rc;
}
