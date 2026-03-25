#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h> 

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>

#include <ebpf_firewall_common.h>
#include <ebpf_firewall_core.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_utils.h>


static void trim(char *s) {
    size_t n = strlen(s);
    size_t i = 0, j = n;
    while (i < n && isspace((unsigned char)s[i])) i++;
    while (j > i && isspace((unsigned char)s[j-1])) j--;
    if (i) memmove(s, s+i, j-i);
    s[j-i] = '\0';
}

static char* slurp_first_line(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return NULL;
    char* line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, f);
    fclose(f);
    if (n <= 0) { free(line); return NULL; }
    trim(line);
    if (!*line) { free(line); return NULL; }
    return line;
}

static int looks_valid_serial(const char* s) {
    if (!s || !*s) return 0;
    // reject common placeholders
    if (!strcasecmp(s, "None")) return 0;
    if (!strcasecmp(s, "Unknown")) return 0;
    if (!strcasecmp(s, "To Be Filled By O.E.M.") || !strcasecmp(s, "To be filled by O.E.M.")) return 0;
    if (!strcmp(s, "00000000-0000-0000-0000-000000000000")) return 0;
    return 1;
}

static void upper_inplace(char* s) {
    for (; *s; ++s) *s = (char)toupper((unsigned char)*s);
}

/* ---------- board serial (DMI) with fallbacks ---------- */

static char* get_board_serial(void) {
    const char* candidates[] = {
        "/sys/class/dmi/id/board_serial",
        "/sys/class/dmi/id/product_uuid",
        "/sys/class/dmi/id/board_asset_tag",
        NULL
    };
    for (int i=0; candidates[i]; i++) {
        char* s = slurp_first_line(candidates[i]);
        if (s && looks_valid_serial(s)) return s;
        free(s);
    }
    // /proc/cpuinfo "Serial" (e.g., Raspberry Pi)
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char *line = NULL; size_t cap = 0;
        while (getline(&line, &cap, f) > 0) {
            if (!strncasecmp(line, "Serial", 6)) {
                char* colon = strchr(line, ':');
                if (colon) {
                    char* s = strdup(colon+1);
                    if (s) { trim(s); fclose(f); free(line); if (looks_valid_serial(s)) return s; free(s); break; }
                }
            }
        }
        free(line);
        fclose(f);
    }
    return NULL;
}

/* ---------- first physical MAC (non-loopback, non-virtual-ish) ---------- */

static int is_bad_mac(const unsigned char* mac, int len) {
    if (len < 6) return 1;
    int all0 = 1, allF = 1;
    for (int i=0; i<len; i++) {
        if (mac[i] != 0x00) all0 = 0;
        if (mac[i] != 0xFF) allF = 0;
    }
    return all0 || allF;
}

static int looks_virtual_name(const char* name) {
    return !strncmp(name, "lo", 2) ||
           !strncmp(name, "docker", 6) ||
           !strncmp(name, "veth", 4) ||
           !strncmp(name, "br-", 3) ||
           !strncmp(name, "virbr", 5) ||
           !strncmp(name, "tun", 3) ||
           !strncmp(name, "tap", 3);
}

static char* first_physical_mac_hex(void) {
    struct ifaddrs* ifs = NULL;
    if (getifaddrs(&ifs) != 0) return NULL;

    char* out = NULL;
    for (struct ifaddrs* it = ifs; it; it = it->ifa_next) {
        if (!it->ifa_addr) continue;
        if (it->ifa_addr->sa_family != AF_PACKET) continue;
        if (it->ifa_flags & IFF_LOOPBACK) continue;
        const char* name = it->ifa_name ? it->ifa_name : "";
        if (looks_virtual_name(name)) continue;

        struct sockaddr_ll* sll = (struct sockaddr_ll*)it->ifa_addr;
        if (sll->sll_halen < 6) continue;
        if (is_bad_mac(sll->sll_addr, sll->sll_halen)) continue;

        size_t outlen = sll->sll_halen * 2;
        out = (char*)malloc(outlen + 1);
        if (!out) break;
        static const char* hex="0123456789ABCDEF";
        for (int i=0;i<sll->sll_halen;i++){
            out[i*2]   = hex[(sll->sll_addr[i]>>4)&0xF];
            out[i*2+1] = hex[(sll->sll_addr[i])&0xF];
        }
        out[outlen] = '\0';
        break;
    }
    freeifaddrs(ifs);
    return out;
}

/* ---------- root disk serial ---------- */

/* Find the device path that is mounted at "/" from /proc/mounts */
static char* root_mount_device(void) {
    FILE* f = fopen("/proc/mounts", "r");
    if (!f) return NULL;
    char dev[PATH_MAX], mnt[PATH_MAX], fs[64];
    char buf[PATH_MAX*2];
    char* out = NULL;
    while (fgets(buf, sizeof(buf), f)) {
        if (sscanf(buf, "%1023s %1023s %63s", dev, mnt, fs) == 3) {
            if (!strcmp(mnt, "/")) {
                out = strdup(dev);
                break;
            }
        }
    }
    fclose(f);
    return out;
}

/* Reduce a partition name to base disk (sda1 -> sda, nvme0n1p2 -> nvme0n1, mmcblk0p1 -> mmcblk0) */
static void to_base_disk(char* name) {
    size_t n = strlen(name);
    // If nvme...pN or mmcblk...pN -> strip trailing 'p<digits>'
    char* p = NULL;
    if ((p = strrchr(name, 'p'))) {
        int all_digits = 1;
        for (char* q = p+1; *q; q++) if (!isdigit((unsigned char)*q)) { all_digits = 0; break; }
        if (all_digits) *p = '\0';
        return;
    }
    // Else strip trailing digits (sda1 -> sda)
    while (n>0 && isdigit((unsigned char)name[n-1])) name[--n] = '\0';
}

/* Read disk serial from sysfs: /sys/class/block/<base>/device/serial */
static char* disk_serial_from_sys(const char* devpath) {
    // devpath like /dev/sda1, /dev/nvme0n1p2, /dev/mapper/...
    const char* base = strrchr(devpath, '/');
    if (!base) return NULL;
    base++;
    char blk[NAME_MAX+1]; snprintf(blk, sizeof(blk), "%s", base);

    // /dev/mapper/dm-* -> find actual dm name
    if (!strncmp(blk, "mapper/", 7)) {
        // Not typical here; keep as-is.
    }
    // If it's a partition, reduce to base
    to_base_disk(blk);

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/sys/class/block/%s/device/serial", blk);
    char* s = slurp_first_line(path);
    if (s && looks_valid_serial(s)) return s;
    free(s);

    // Try WWID as fallback
    snprintf(path, sizeof(path), "/sys/class/block/%s/device/wwid", blk);
    s = slurp_first_line(path);
    if (s && looks_valid_serial(s)) return s;
    free(s);

    return NULL;
}

/* Fallback: match /dev/disk/by-id symlink pointing to our root dev or its base, use its filename */
static char* disk_serial_from_byid(const char* devpath) {
    char devbase[NAME_MAX+1];
    const char* b = strrchr(devpath, '/'); b = b ? b+1 : devpath;
    snprintf(devbase, sizeof(devbase), "%s", b);
    to_base_disk(devbase);

    DIR* d = opendir("/dev/disk/by-id");
    if (!d) return NULL;
    struct dirent* ent;
    char linkpath[PATH_MAX], target[PATH_MAX];
    char* best = NULL;

    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;
        snprintf(linkpath, sizeof(linkpath), "/dev/disk/by-id/%s", ent->d_name);
        ssize_t n = readlink(linkpath, target, sizeof(target)-1);
        if (n <= 0) continue;
        target[n] = '\0';
        const char* tb = strrchr(target, '/');
        tb = tb ? tb+1 : target;

        // If symlink points to this base (or partition), accept
        if (!strncmp(tb, devbase, strlen(devbase))) {
            // Use the by-id filename (often contains model+serial)
            best = strdup(ent->d_name);
            break;
        }
    }
    closedir(d);
    return best;
}

static char* get_root_disk_serial(void) {
    char* dev = root_mount_device();
    if (!dev) return NULL;

    char* s = disk_serial_from_sys(dev);
    if (!s) s = disk_serial_from_byid(dev);
    free(dev);
    return s;
}

/* ---------- SHA-256 hex ---------- */

static char* sha256_hex(const unsigned char* data, size_t len) {
    unsigned char dig[SHA256_DIGEST_LENGTH];
    SHA256(data, len, dig);
    char* out = (char*)malloc(SHA256_DIGEST_LENGTH*2 + 1);
    static const char* hex = "0123456789abcdef";
    for (int i=0;i<SHA256_DIGEST_LENGTH;i++){ out[i*2]=hex[(dig[i]>>4)&0xF]; out[i*2+1]=hex[dig[i]&0xF]; }
    out[SHA256_DIGEST_LENGTH*2] = '\0';
    return out;
}

/* ---------- main ---------- */

int get_machine_id(char * machine_id) {
    if (machine_id == NULL)
        return -1;

    char* board = get_board_serial();            if (board) upper_inplace(board);
    char* mac   = first_physical_mac_hex();      // already uppercase
    char* disk  = get_root_disk_serial();        if (disk) upper_inplace(disk);

#if 0    
    fprintf(stderr, "board_serial = %s\n", board ? board : "(none)");
    fprintf(stderr, "disk_serial  = %s\n",  disk ? disk  : "(none)");
    fprintf(stderr, "mac_address  = %s\n",  mac  ? mac   : "(none)");
#endif

    // Build canonical string (include labels to avoid ambiguity)
    // Use placeholders to keep stability of the format if some fields are missing.
    const char* nb = board ? board : "N/A";
    const char* nd = disk  ? disk  : "N/A";
    const char* nm = mac   ? mac   : "N/A";

    // Concatenate with fixed separators
    char buf[4096];
    int n = snprintf(buf, sizeof(buf), "BOARD:%s|DISK:%s|MAC:%s", nb, nd, nm);
    if (n < 0 || n >= (int)sizeof(buf)) {
        LOG_E("internal error: id concat too long\n");
        free(board); free(mac); free(disk);
        return -1;
    }

    // Produce fixed-length machine_id = SHA-256 hex of the canonical string
    char* id = sha256_hex((const unsigned char*)buf, (size_t)n);
    if (!id) {
        LOG_E("sha256 error\n");
        free(board); free(mac); free(disk);
        return -1;
    }
    LOG_D("Machine id is %s\n", id);
    snprintf(machine_id, 256, "%s", id);

    free(id);
    free(board); free(mac); free(disk);
    return 0;
}

static char* slurp_fd(FILE* f, size_t* out_len) {
    size_t cap = 4096, n = 0;
    char* buf = (char*)malloc(cap);
    if (!buf) return NULL;
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (n+1 >= cap) {
            cap *= 2;
            char* nb = (char*)realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        buf[n++] = (char)c;
    }
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

static void trim_inplace(char* s) {
    size_t len = strlen(s);
    size_t i=0, j=len;
    while (i<len && isspace((unsigned char)s[i])) i++;
    while (j>i && isspace((unsigned char)s[j-1])) j--;
    size_t newlen = j-i;
    memmove(s, s+i, newlen);
    s[newlen] = '\0';
}

/* ---- Base64 decode using OpenSSL BIO (NO_NL) ---- */
static unsigned char* b64_decode(const char* in, size_t inlen, size_t* outlen) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(in, (int)inlen);
    if (!b64 || !bmem) { if (b64) BIO_free(b64); if (bmem) BIO_free(bmem); return NULL; }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_push(b64, bmem);

    size_t cap = (inlen*3)/4 + 8;
    unsigned char* out = (unsigned char*)malloc(cap);
    if (!out) { BIO_free_all(bio); return NULL; }

    int n = BIO_read(bio, out, (int)cap);
    if (n <= 0) { free(out); BIO_free_all(bio); return NULL; }

    *outlen = (size_t)n;
    BIO_free_all(bio);
    return out;
}

/* ---- Load server public key (PEM) ---- */
static EVP_PKEY* load_public_key(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    EVP_PKEY* pk = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    return pk;
}

/* ---- Naive JSON helpers (no external lib) ---- */
static char* find_key(char* json, const char* key) {
    size_t klen = strlen(key);
    char* p = json;
    while ((p = strstr(p, key))) {
        /* Ensure it's a JSON key: must be quoted "key" (caller includes quotes) */
        /* And next non-ws char after key should be ':' */
        char* q = p + klen;
        while (*q && isspace((unsigned char)*q)) q++;
        if (*q == ':') return q+1;
        p = p + 1;
    }
    return NULL;
}

/* Get string value at position (after colon). Returns malloc'd string (unescaped minimal), or NULL */
static char* get_json_string_after_colon(const char* pos) {
    while (*pos && isspace((unsigned char)*pos)) pos++;
    if (*pos != '\"') return NULL;
    pos++;
    size_t cap = 128, n = 0;
    char* out = (char*)malloc(cap);
    if (!out) return NULL;
    int esc = 0;
    for (; *pos; ++pos) {
        char c = *pos;
        if (esc) {
            /* minimal unescape for \" and \\ and \n, \t, \r; ignore \uXXXX for simplicity */
            char v = c;
            if (c=='n') v = '\n'; else if (c=='t') v = '\t'; else if (c=='r') v = '\r';
            if (n+1 >= cap) { cap*=2; char* nb = (char*)realloc(out, cap); if(!nb){ free(out); return NULL; } out=nb; }
            out[n++] = v;
            esc = 0;
        } else if (c == '\\') {
            esc = 1;
        } else if (c == '\"') {
            break;
        } else {
            if (n+1 >= cap) { cap*=2; char* nb = (char*)realloc(out, cap); if(!nb){ free(out); return NULL; } out=nb; }
            out[n++] = c;
        }
    }
    out[n] = '\0';
    return out;
}

/* Get integer value at position (after colon). */
static int get_json_int_after_colon(const char* pos, int* ok) {
    while (*pos && isspace((unsigned char)*pos)) pos++;
    char* endptr = NULL;
    long v = strtol(pos, &endptr, 10);
    if (endptr == pos) { *ok = 0; return 0; }
    *ok = 1;
    return (int)v;
}

/* Extract raw payload JSON substring (including outer { ... }) */
static int extract_payload_raw(const char* lic_json, const char** out_start, size_t* out_len) {
    const char* key = "\"payload\"";
    const char* kpos = strstr(lic_json, key);
    if (!kpos) return 0;
    const char* pos = strchr(kpos, '{');
    if (!pos) return 0;

    const char* p = pos;
    int depth = 0, in_str = 0, esc = 0;
    for (; *p; ++p) {
        char c = *p;
        if (in_str) {
            if (esc) esc = 0;
            else if (c == '\\') esc = 1;
            else if (c == '"') in_str = 0;
        } else {
            if (c == '"') in_str = 1;
            else if (c == '{') { if (depth == 0) *out_start = p; depth++; }
            else if (c == '}') { depth--; if (depth == 0) { *out_len = (size_t)(p - *out_start + 1); return 1; } }
        }
    }
    return 0;
}

static char* extract_signature_b64(char* lic_json) {
    const char* valpos = find_key(lic_json, "\"signature\"");
    if (!valpos) return NULL;
    return get_json_string_after_colon(valpos);
}

static char* extract_algorithm(char* lic_json) {
    const char* valpos = find_key(lic_json, "\"algorithm\"");
    if (!valpos) return NULL;
    return get_json_string_after_colon(valpos);
}

/* ---- Verify RSA-SHA256 over payload bytes ---- */
static int verify_signature(EVP_PKEY* pub, const unsigned char* msg, size_t msg_len,
                            const unsigned char* sig, size_t sig_len) {
    int ok = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) != 1) goto done;
    if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) != 1) goto done;
    ok = (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1);
done:
    EVP_MD_CTX_free(ctx);
    return ok;
}


/* Convert struct tm (assumed UTC) to time_t without timegm(). */
static time_t timegm_compat(struct tm *tm_utc) {
    char *old_tz = getenv("TZ");
    char *backup = old_tz ? strdup(old_tz) : NULL;

    setenv("TZ", "UTC", 1);
    tzset();
    time_t t = mktime(tm_utc); /* interpreted as UTC because TZ=UTC */

    if (backup) {
        setenv("TZ", backup, 1);
        free(backup);
    } else {
        unsetenv("TZ");
    }
    tzset();
    return t;
}

/* Parse strict "YYYY-MM-DDTHH:MM:SSZ" (UTC) */
static int parse_iso8601_utc(const char *s, time_t *out) {
    struct tm tm = {0};
    char *end = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
    if (!end || *end != '\0') return 0;
    tm.tm_isdst = -1;
    *out = timegm_compat(&tm);
    return (*out != (time_t)-1);
}


int get_license_status() {
    char real_machine_id[256];
    if (get_machine_id(real_machine_id) < 0) {
        LOG_E("Failed to get machine id of this device\n");
        return -1;
    }

    /* Read license.b64 */
    char* lic_b64 = NULL;
    size_t lic_b64_len = 0;
    
    char* lic_path = getenv(LICENSE_PATH);
    if (!lic_path) {
        LOG_E( "ERROR: Failed to read env : %s\n", LICENSE_PATH);
        return 1;
    }

    FILE* f = fopen(lic_path, "rb");
    if (!f) {
        /* Under heavy load, fd pressure can make fopen fail transiently. */
        LOG_E("Cannot open license file '%s': %s\n", lic_path, strerror(errno));
        if (errno == EMFILE || errno == ENFILE || errno == ENOMEM || errno == EAGAIN) {
            return -3;
        }
        return -1;
    }
    lic_b64 = slurp_fd(f, &lic_b64_len);
    fclose(f);
    
    if (!lic_b64) { LOG_E("Failed to read license file\n"); return -1; }
    trim_inplace(lic_b64);

    /* Base64 decode -> license JSON */
    size_t lic_json_len = 0;
    unsigned char* lic_json_bin = b64_decode(lic_b64, strlen(lic_b64), &lic_json_len);
    if (!lic_json_bin) { LOG_E("Base64 decode failed\n"); free(lic_b64); return -1; }

    char* lic_json = (char*)malloc(lic_json_len + 1);
    if (!lic_json) { free(lic_b64); free(lic_json_bin); return -1; }
    memcpy(lic_json, lic_json_bin, lic_json_len);
    lic_json[lic_json_len] = '\0';

    /* Extract algorithm */
    char* algo = extract_algorithm(lic_json);
    if (!algo || strcmp(algo, "RSA-SHA256") != 0) {
        LOG_E("Unsupported or missing algorithm (got: %s)\n", algo ? algo : "NULL");
        free(algo); free(lic_b64); free(lic_json_bin); free(lic_json);
        return -1;
    }

    /* Extract raw payload JSON bytes (exactly as signed) */
    const char* payload_start = NULL;
    size_t payload_len = 0;
    if (!extract_payload_raw(lic_json, &payload_start, &payload_len)) {
        LOG_E("Failed to locate payload JSON\n");
        free(algo); free(lic_b64); free(lic_json_bin); free(lic_json);
        return -1;
    }

    /* Extract signature (Base64 -> bytes) */
    char* sig_b64 = extract_signature_b64(lic_json);
    if (!sig_b64) {
        LOG_E("Missing signature field\n");
        free(algo); free(lic_b64); free(lic_json_bin); free(lic_json);
        return -1;
    }
    size_t sig_len = 0;
    unsigned char* sig = b64_decode(sig_b64, strlen(sig_b64), &sig_len);
    if (!sig) {
        LOG_E("Signature Base64 decode failed\n");
        free(sig_b64); free(algo); free(lic_b64); free(lic_json_bin); free(lic_json);
        return -1;
    }

    /* Load server public key and verify */
    char* pubkey_path = getenv(PUBKEY_PATH);
    if (!pubkey_path) {
        LOG_E( "ERROR: Failed to read env : %s\n", PUBKEY_PATH);
        return -1;
    }

    EVP_PKEY* pub = load_public_key(pubkey_path);
    if (!pub) {
        LOG_E("Failed to load public key: %s\n", pubkey_path);
        free(sig); free(sig_b64); free(algo); free(lic_b64); free(lic_json_bin); free(lic_json);
        return -1;
    }

    int verified = verify_signature(pub,
                                    (const unsigned char*)payload_start,
                                    payload_len,
                                    sig, sig_len);

    if (!verified) {
        LOG_E("Invalid license file\n");
        return -1;
    }

    //printf("Signature: %s\n", verified ? "VALID" : "INVALID");

    /* Optional: parse fields inside payload for convenience */
    char* payload_copy = (char*)malloc(payload_len + 1);
    memcpy(payload_copy, payload_start, payload_len);
    payload_copy[payload_len] = '\0';

    /* Extract fields (naive scan) */
    char* pos;
    char* machine_id = NULL; char* updated_at = NULL; char* license_type = NULL;
    int oknum=0, duration=0, feature=0;

    pos = find_key(payload_copy, "\"machine_id\"");
    if (pos) machine_id = get_json_string_after_colon(pos);

    pos = find_key(payload_copy, "\"updated_at\"");
    if (pos) updated_at = get_json_string_after_colon(pos);

    pos = find_key(payload_copy, "\"license_type\"");
    if (pos) license_type = get_json_string_after_colon(pos);

    pos = find_key(payload_copy, "\"duration\"");
    if (pos) duration = get_json_int_after_colon(pos, &oknum);

    pos = find_key(payload_copy, "\"feature\"");
    if (pos) feature = get_json_int_after_colon(pos, &oknum);

    //printf("Payload (raw JSON): %.*s\n", (int)payload_len, payload_start);
    //printf("Fields:\n");
    LOG_D("  machine_id   : %s\n", machine_id ? machine_id : "(none)");
    LOG_D("  updated_at   : %s\n", updated_at ? updated_at : "(none)");
    LOG_D("  duration     : %d\n", duration);
    LOG_D("  feature      : %d\n", feature);
    LOG_D("  license_type : %s\n", license_type ? license_type : "(none)");

    int ret = -1;
    if (machine_id && strncmp(real_machine_id, machine_id, strlen(real_machine_id)) == 0) {
        if (!license_type) goto cleanup;
        LOG_I("License : %s mode\n", license_type);
        
        time_t created_utc;
        if (!parse_iso8601_utc(updated_at, &created_utc)) {
            LOG_E("invalid date_string (expect UTC like 2025-09-25T01:36:01Z)\n");
            goto cleanup;
        }

        /* Compute expiry = created + duration_days * 86400 */
        const long long SECS_PER_DAY = 86400LL;
        long long created_ll = (long long)created_utc;
        long long expiry_ll  = created_ll + (long long)duration * SECS_PER_DAY;

        time_t now = time(NULL);
        long long now_ll = (long long)now;

        if (now_ll >= expiry_ll) {
            ret = -2;
            LOG_W("License : Expired, please purchase new license\n");
            goto cleanup;
        }

        long long rem_secs = expiry_ll - now_ll;
        long long days_left = (rem_secs + SECS_PER_DAY - 1) / SECS_PER_DAY;

        if (days_left < 0) days_left = 0; /* just in case */
        LOG_I("License : %lld days left\n", days_left);

        ret = 0;
        goto cleanup;
    }

    LOG_E("Machine id is different\n");
    
cleanup:
    /* Cleanup */
    EVP_PKEY_free(pub);
    free(machine_id); free(updated_at); free(license_type);
    free(payload_copy);
    free(sig); free(sig_b64); free(algo);
    free(lic_b64); free(lic_json_bin); free(lic_json);
    return ret;
}