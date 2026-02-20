#ifndef NGX_HTTP_ACL_MODULE_TYPE_H
#define NGX_HTTP_ACL_MODULE_TYPE_H

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <uthash.h>
#include <utarray.h>
#include <utlist.h>
#include <maxminddb.h>
#include <pthread.h>

#define NGX_HTTP_ACL_FALSE                   (0)
#define NGX_HTTP_ACL_TRUE                    (1)

#define NGX_HTTP_ACL_FAIL                    (-1)
#define NGX_HTTP_ACL_SUCCESS                 (1)
#define NGX_HTTP_ACL_PROCESSING              (2)
#define NGX_HTTP_ACL_MALLOC_ERROR            (3)
#define NGX_HTTP_ACL_KEY_EXISTS              (4)
#define NGX_HTTP_ACL_KEY_NOT_EXISTS          (5)
#define NGX_HTTP_ACL_BAD                     (6)
#define NGX_HTTP_ACL_ALLOW                   (7)
#define NGX_HTTP_ACL_CAPTCHA_CHALLENGE       (8)
#define NGX_HTTP_ACL_CAPTCHA_BAD             (9)
#define NGX_HTTP_ACL_CAPTCHA_PASS            (10)
#define NGX_HTTP_ACL_FAULT                   (11)
#define NGX_HTTP_ACL_NEXT_FILTER             (12)
#define NGX_HTTP_ACL_ALREADY_EXISTS          (13)

#define NGX_HTTP_ACL_HCAPTCHA                (1)
#define NGX_HTTP_ACL_RECAPTCHA_V2_CHECKBOX   (2)
#define NGX_HTTP_ACL_RECAPTCHA_V2_INVISIBLE  (3)
#define NGX_HTTP_ACL_RECAPTCHA_V3            (4)

#define NGX_HTTP_ACL_UID_LEN                 (64)
#define NGX_HTTP_ACL_RULE_MAX_LEN            (256 * 4 * 8)

#define NGX_HTTP_ACL_SHARE_MEMORY_CC_REQ_DNEY_NAME               ("__HTTP_NGX_ACL_CC_REQ_DENY_SHM__")
#define NGX_HTTP_ACL_SHARE_MEMORY_REQ_MIN_SIZE                   (1024 * 1024 * 20)

#define NGX_HTTP_ACL_SHARE_MEMORY_CC_RSP_DNEY_NAME               ("__HTTP_NGX_ACL_CC_RSP_DENY_SHM__")
#define NGX_HTTP_ACL_SHARE_MEMORY_RSP_MIN_SIZE                   (1024 * 1024 * 50)

#define NGX_HTTP_ACL_SHARE_MEMORY_SERVER_ACL_NAME                ("__HTTP_NGX_ACL_SERVER_ACL_SHM__")
#define NGX_HTTP_ACL_SHARE_MEMORY_SERVER_ACL_MIN_SIZE            (1024 * 1024 * 10)

#define NGX_HTTP_ACL_SHARE_MEMORY_OPTIMIZE_MIN_SIZE              (1024 * 1024)

#define MAX_HEADER_CODE_COUNT                                    600

typedef enum {
    ACTION_FLAG_NONE                = 0x0,
    ACTION_FLAG_UNSET               = 0x1,
    ACTION_FLAG_DECLINE             = 0x2,
    ACTION_FLAG_FOLLOW              = 0x4,
    ACTION_FLAG_RETURN              = 0x8,
    ACTION_FLAG_REG_CONTENT         = 0x10,
    ACTION_FLAG_STR                 = 0x20,
    ACTION_FLAG_HTML                = 0x40,
    ACTION_FLAG_FROM_WHITE_LIST     = 0x80,
    ACTION_FLAG_FROM_BLACK_LIST     = 0x100,
    ACTION_FLAG_FROM_CC_DENY        = 0x200,
    ACTION_FLAG_FROM_MODSECURITY    = 0x400,
    ACTION_FLAG_FROM_CAPTCHA        = 0x800,
    ACTION_FLAG_FROM_UNDER_ATTACK   = 0x1000,
    ACTION_FLAG_FROM_VERIFY_BOT     = 0x2000,
    ACTION_FLAG_CAPTCHA             = 0x4000,
    ACTION_FLAG_UNDER_ATTACK        = 0X8000
} action_flag_e;


typedef struct action_s {
    action_flag_e flag;
    struct action_s* next;
    struct action_s* prev;
    union {
        ngx_uint_t http_status;

        struct {
            ngx_uint_t http_status;
            ngx_str_t* str;
        } extra_str;

        struct {
            ngx_uint_t http_status;
            ngx_str_t* html;
        } extra_html;

    } extra;
} action_t;

typedef struct ngx_http_acl_ctx_s {
    ngx_int_t                       checked;                                    /**< Checked status */
    ngx_int_t                       matched;                                    /**< Whether this request was matched the ACL rule */
    time_t                          time;                                       /**< Context created time */
    ngx_int_t                       read_body_done;
    ngx_int_t                       waiting_more_body;                          /**< Whether to wait to read more request bodies */
    ngx_int_t                       has_req_body;                               /**< Field req_body Whether the request body has been stored */
    ngx_int_t                       register_content_handler:1;                 /**< Whether the content handler has been or should be registered */
    ngx_buf_t                       req_body;                                   /**< Request body */
    action_t                       *action_chain;
} ngx_http_acl_ctx_t;


typedef enum {
     VM_CODE_NOP,                   /**< Empty instruction, do nothing and continue executing the next instruction. */
     VM_CODE_PUSH_INT,              /**< Push an integer onto the stack. */
     VM_CODE_PUSH_STR,              /**< Push a string onto the stack. */
     VM_CODE_PUSH_CLIENT_IP,        /**< Push the client IP (struct in_addr or struct_in6addr) onto the stack. */
     VM_CODE_PUSH_URL,              /**< Push URL onto the stack. */
     VM_CODE_PUSH_QUERY_STRING,     /**< Push the value corresponding to the key of the query string onto the stack. */
     VM_CODE_PUSH_REFERER,          /**< Push referer onto the stack. */
     VM_CODE_PUSH_USER_AGENT,       /**< Push user-agent onto the stack. */
     VM_CODE_PUSH_HEADER_IN,        /**< Push the value corresponding to the key in the request header onto the stack. */
     VM_CODE_PUSH_COOKIE,           /**< Push the value corresponding to the key in the cookie onto the stack. */
     // VM_CODE_POP,                /**< */
     // VM_CODE_TOP,                /**< */
     VM_CODE_OP_NOT,                /**< Invert the Boolean value on the top of the stack */
     VM_CODE_OP_AND,                /**< Pops two Boolean values, logically ANDs and then pushes them onto the stack. */
     VM_CODE_OP_OR,                 /**< Pop two Boolean values, logical OR and push them onto the stack */
     VM_CODE_OP_CONTAINS,           /**< Pop two strings, determine whether the first popped string is a substring of the second popped string, and push the result onto the stack */
     VM_CODE_OP_MATCHES,            /**< Pops two strings, compiles the first string into a regular expression, performs regular matching on the second string, and pushes the result onto the stack. */
     VM_CODE_OP_EQUALS,             /**< Pops two strings to determine whether the two strings are equal, and pushes the result onto the stack. */
     VM_CODE_OP_BELONG_TO,          /**< Pops an IP block and an IP in sequence, determines whether the IP is included in the IP block, and pushes the result onto the stack. */
     VM_CODE_OP_SQLI_DETN,          /**< Pops a string to detect whether there is SQL injection and pushes the result onto the stack. */
     VM_CODE_OP_XSS_DETN,           /**< Pops a string to detect whether there is an XSS attack and pushes the result onto the stack. */
     VM_CODE_ACT_RETURN,            /**< Returns the specified http status code if the Boolean value at the top of the stack is true. */
     VM_CODE_ACT_ALLOW              /**< If the Boolean value at the top of the stack is true, the request will be released. */
} vm_code_type_e;


typedef enum {
     VM_DATA_VOID,                  /**< Untyped data, should be ignored. */
     VM_DATA_STR,                   /**< string type */
     VM_DATA_INT,                   /**<integer type*/
     VM_DATA_BOOL,                  /**< Boolean type */
     VM_DATA_IPV4,                  /**< IPV4 */
#if (NGX_HAVE_INET6)
     VM_DATA_IPV6                   /**< IPV6 */
#endif
} vm_data_type_e;

typedef struct ipv4_s {
     u_char text[32];               /**< dotted decimal notation */
     uint32_t prefix;               /**< Equivalent to the integer form of 192.168.1.0 in 192.168.1.0/24 */
     uint32_t suffix;               /**< Equivalent to the bit representation of 24 in 192.168.1.0/24 (network byte order) */
     uint32_t suffix_num;           /**< Equivalent to 24 in 192.168.1.0/24 */
} ipv4_t;

#if (NGX_HAVE_INET6)
typedef struct ipv6_s {
     u_char text[64];               /**< colon hexadecimal notation */
     uint8_t prefix[16];            /**< Equivalent to the integer form of ffff::ffff in ffff::ffff/64 */
     uint8_t suffix[16];            /**< Equivalent to the bit representation of 64 in ffff::ffff/64 (network byte order) */
     uint32_t suffix_num;           /**< Equivalent to 64 in ffff::ffff/64 */
} ipv6_t;

#endif

typedef union inx_addr_u {
    struct in_addr  ipv4;
#if (NGX_HAVE_INET6)
    struct in6_addr ipv6;
#endif
} inx_addr_t;

typedef struct vm_stack_arg_s {
     vm_data_type_e type[4];        /**<The type of each parameter */
     size_t argc;                   /**<Number of parameters */
     union {
         int int_val;
         ngx_str_t str_val;
         uint8_t bool_val;
         ipv4_t ipv4_val;
#if (NGX_HAVE_INET6)
         ipv6_t ipv6_val;
#endif
         inx_addr_t inx_addr_val;
     } value[4];                    /**< value of each parameter */
     struct vm_stack_arg_s *utstack_handle; /**< utstack key member */
} vm_stack_arg_t;


typedef struct vm_code_s {
     vm_code_type_e type;           /**< instruction type */
     struct vm_stack_arg_s argv;    /**< command parameters */
} vm_code_t;



#define FIELD_COUNT 12
#define OPERATOR_COUNT 12

typedef enum field_s {
    Field_Cookie = 0,
    Field_Geo,
    Field_IP,
    Field_Referer,
    Field_RequestMethod,
    Field_URIPath,
    Field_URIQueryString,
    Field_UserAgent,
    Field_Header,
    Field_Request_Frequency,
    Field_ASN,
    Field_Response_Frequency,
    Field_Unknown,
} field_e;

typedef enum operator_s {
    Operator_equals,
    Operator_contains,
    Operator_is_in,
    Operator_not_equals,
    Operator_not_contains,
    Operator_not_is_in,
    Operator_bigger,
    Operator_bigger_equal,
    Operator_small,
    Operator_small_equal,
    Operator_equal_equal,
    Operator_regex,
    Operator_Unknown
} operator_e;

typedef enum acl_rule_aciton_s {
    ACTION_UNKNOWN = 0,
    ACTION_ALLOW,
    ACTION_DROP,
    ACTION_DENY,
    ACTION_DROP_BLOCK,
    ACTION_HCAPTCHA
} acl_rule_aciton_e;


typedef enum acl_rule_return_s {
    ACL_RETURN_INTERNAL_ERROR = 0,
    ACL_RETURN_ALLOW_RULE,
    ACL_RETURN_DROP,
    ACL_RETURN_DENY,
    ACL_RETURN_DROP_BLOCK,
    ACL_RETURN_CAPTCHA_START,
    ACL_RETURN_ALLOW_NO_RULE,
    ACL_RETURN_NO_LICENSE
} acl_rule_return_e;

typedef struct comparative_expression_s
{
    field_e                             field;
    operator_e                          op;
    char                               *name_str;
    char                               *exp_str;
    ngx_int_t                           exp_value;
} comparative_expression_t;

typedef enum {
    ACL_RULE_TOKEN_NODE,
    ACL_RULE_TOKEN_AND,
    ACL_RULE_TOKEN_OR,
    ACL_RULE_TOKEN_LPAREN,
    ACL_RULE_TOKEN_RPAREN,
    ACL_RULE_TOKEN_END
} acl_rule_node_type_e;

typedef struct acl_rule_node_s {
    acl_rule_node_type_e                type;
    comparative_expression_t           *exp_node;
} acl_rule_node_t;

typedef struct lru_cache_result_s {
    int                                 status;
    void                                **data;
} lru_cache_result_t;

typedef lru_cache_result_t lru_cache_add_result_t;
typedef lru_cache_result_t lru_cache_find_result_t;

typedef enum {
    std,                            /**< malloc */
    general_pool,                    /**< ngx_pool_t */
    slab_pool                       /**< ngx_slab_pool_t */
} mem_pool_type_e;

typedef struct memo_pool_s {
    mem_pool_type_e                    type;
    size_t                             used_mem;
    union {
        ngx_pool_t                     *general_pool;
        ngx_slab_pool_t                *slab_pool;
    } native_pool;
} mem_pool_t;

typedef struct lru_cache_item_s {
    u_char                             *key_ptr;
    size_t                              key_byte_length;
    void                               *data;
    struct lru_cache_item_s            *prev;
    struct lru_cache_item_s            *next;
    UT_hash_handle                      hh;
} lru_cache_item_t;

typedef struct lru_cache_s {
    time_t                              last_eliminate;
    mem_pool_t                          pool;
    size_t                              capacity;
    lru_cache_item_t                    *hash_head;
    lru_cache_item_t                    *chain_head;
} lru_cache_t;

typedef struct acl_rule_s {
    mem_pool_t                          pool;
    acl_rule_aciton_e                   action;
    ngx_int_t                           priority;
    int                                 acl_rule_node_list_count;
    acl_rule_node_t                    *acl_rule_node_list;
} acl_rule_t;

typedef struct acl_rule_list_s {
    mem_pool_t                           pool;
    int                                  acl_rule_list_id;
    int                                  acl_rule_count;
    acl_rule_t                          *acl_rule_list;
    struct acl_rule_list_s              *prev;
    struct acl_rule_list_s              *next;
} acl_rule_list_t;

typedef struct server_acl_rule_s {
    mem_pool_t                          pool;
    
    acl_rule_list_t                    *head;
    acl_rule_list_t                    *tail;
    
    ngx_int_t                           max_req_freq_time; // Request Frequency
    ngx_int_t                           max_rsp_freq_time; // Response Frequency

    ngx_int_t                           header_out_codes[MAX_HEADER_CODE_COUNT];
    size_t                              header_out_code_count;
} server_acl_rule_t;


typedef struct time_node_s {
    struct time_node_s                  *prev;
    struct time_node_s                  *next;
    time_t                               time;
    int                                  count;
} time_node_t;

typedef struct time_rec_s {
    time_node_t                         *head;
    time_node_t                         *tail;
} time_rec_t;

typedef struct header_code_rec_s {
    time_rec_t                           rsp_time_rec;
} header_code_rec_t;

typedef struct header_rec_s {
    header_code_rec_t                    header_rsp_time_rec[MAX_HEADER_CODE_COUNT];
} header_rec_t;

typedef enum ip_statis_type_s {
    IP_STATIS_REQUEST,
    IP_STATIS_RESPONSE
} ip_statis_type_e;

typedef struct ip_statis_s {
    ip_statis_type_e                     ip_statis_type;
    union {
        time_rec_t                      *req_time_rec;
        header_rec_t                    *rsp_time_rec;
    } u;
} ip_statis_t;

typedef struct request_freq_s {
    int                                  count;
    int                                  duration;
} request_freq_t;

typedef struct ngx_http_acl_loc_conf_s {
    ngx_int_t                            acl;
} ngx_http_acl_loc_conf_t;

typedef struct ngx_http_acl_main_conf_s {
    ngx_str_t                            acl_geo_database_path;
    MMDB_s                             * geo_db_ctx;
    
    ngx_str_t                            acl_isp_database_path;
    MMDB_s                             * isp_db_ctx;

    ngx_shm_zone_t                     * shm_zone_server_acl_rule;
    ngx_int_t                            acl_server_acl_shm_zone_size;
    server_acl_rule_t                  * server_acl_rule;

    ngx_shm_zone_t                     * shm_zone_cc_req_deny;
    ngx_int_t                            acl_req_shm_zone_size;
    lru_cache_t                        * ip_access_statistics;

    ngx_shm_zone_t                     * shm_zone_cc_rsp_deny;
    ngx_int_t                            acl_rsp_shm_zone_size;
    lru_cache_t                        * ip_response_statistics;

    ngx_int_t                            acl_optimize_period;

    ngx_shm_zone_t                     * shm_zone_optimize_req;
    time_t                             * optimized_req_time;
    
    ngx_shm_zone_t                     * shm_zone_optimize_rsp;
    time_t                             * optimized_rsp_time;
    
} ngx_http_acl_main_conf_t;

typedef struct key_value_s {
    ngx_str_t           key;        /**< 键 */   
    ngx_str_t           value;      /**< 值 */
    UT_hash_handle      hh;         /**< uthash 关键成员 */
} key_value_t;


#ifndef NGX_HTTP_ACL_NO_DEBUG
#define ngx_http_acl_dp_func_start(r) { \
    if (r != NULL) { \
        ngx_http_acl_dpf(r, "%s start", __func__); \
    } \
}


#define ngx_http_acl_dp(r, str) { \
    if (r != NULL) {    \
        ngx_log_debug(NGX_LOG_DEBUG_CORE, (r)->connection->log, 0,  \
            "ngx_acl_debug: ["str"] at %s:%s:%d, ngx_acl", __func__, __FILE__, __LINE__); \
    } \
}


#define ngx_http_acl_dpf(r, fmt, ...) { \
    if (r != NULL) {    \
        ngx_log_debug(NGX_LOG_DEBUG_CORE, (r)->connection->log, 0,  \
            "ngx_acl_debug: ["fmt"] at %s:%s:%d", __VA_ARGS__, __func__, __FILE__, __LINE__); \
    }  \
}


#define ngx_http_acl_dp_func_end(r) { \
    if (r != NULL) { \
        ngx_http_acl_dpf(r, "%s end", __func__); \
    } \
}
#else
#define ngx_http_acl_dp_func_start(...) {}


#define ngx_http_acl_dp(...) {}


#define ngx_http_acl_dpf(...) {}


#define ngx_http_acl_dp_func_end(...) {}
#endif

#define ngx_http_acl_check_flag(origin, flag) (((origin) & (flag)) == (flag))

#define ngx_is_null_str(s) ((s) == NULL || (s)->data == NULL || (s)->len == 0 || ((s)->data[0] == '\0' && (s)->len == 1))

#define ngx_http_acl_is_valid_ptr_value(x) (((x) != NGX_CONF_UNSET_PTR) && ((x) != NULL))

#define ngx_strdup(s) ((u_char*)strdup((char*)(s)));

#define ngx_strcpy(d, s) (strcpy((char*)d, (const char*)s))

#endif
