#include <ebpf_firewall_common.h>
#include <ebpf_firewall_unix.h>
#include <ebpf_firewall_core.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_geo.h>

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
        char *tok = strtok(line, ",");
        if (!tok) continue;
        uint32_t gid = atoi(tok);

        // skip to 5th field
        for (int i = 0; i < 4; i++) tok = strtok(NULL, ",");
        if (!tok || strlen(tok) < 2) continue;

        // compare iso against filters
        for (int i = 0; i < n_filters; i++) {
            if (strcasecmp(tok, iso_filters[i]) == 0) {
                gids = realloc(gids, (ng+1)*sizeof *gids);
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
                     int map_fd) {
    FILE *f = fopen(path, "r");
    if (!f) { LOG_E("Failed to read ipv4.csv"); return -1; }

    char line[MAX_LINE];
    // skip header
    fgets(line, sizeof line, f);

    while (fgets(line, sizeof line, f)) {
        char *cidr = strtok(line, ",");
        char *gid_s = strtok(NULL, ",");
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
        *slash = 0;
        int prefix = atoi(slash+1);

        struct in_addr a;
        if (inet_pton(AF_INET, cidr, &a) != 1)
            continue;
        uint32_t net = a.s_addr;  // keep **network** byte order

        // populate LPM key
        struct lpm_key key = {
            .prefixlen = prefix,
            .ip        = net,
        };
        __u8 val = 1;  // allow

        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0) {
            LOG_E("map_update failed: %s\n", strerror(errno));
        }
    }

    fclose(f);
    return 0;
}

int init_geo(char * loc_path, 
             char * ipv4_path, 
             char   isos[][3], int nisos, 
             int map_fd)
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
    
    if (load_ipv4(ipv4_path, gids, ng, map_fd) < 0) {
        LOG_E("ERROR: loading GEO ipv4 CSV data\n");
        return -1;
    }

    if (gids) free(gids);

    return 0;
}
