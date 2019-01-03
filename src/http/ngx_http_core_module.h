
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_string.h>
#include <ngx_array.h>
#include <ngx_http.h>


typedef struct {
    unsigned                   default_server:1;
    unsigned                   bind:1;

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ngx_uint_t                 deferred_accept;
#endif

    u_char                     addr[INET_ADDRSTRLEN + 6];

} ngx_http_listen_conf_t;


typedef struct {
    in_addr_t                  addr;
    in_port_t                  port;
    int                        family;

    ngx_str_t                  file_name;
    ngx_int_t                  line;

    ngx_http_listen_conf_t     conf;
} ngx_http_listen_t;


/**
 * nginx中的处理一个http的请求分为了8个phase,分别是下面几个阶段

    这里要注意的就是这几个phase的执行是严格按照顺序的,也就是NGX_HTTP_POST_READ_PHASE是第一个,
    而LOG_PHASE是最后一个。只有一个特殊那就是FIND_CONFIG_PHASE,这个的话,有可能会在后面的
    rewrite phase再来调用这个phase。
 */
typedef enum {
    //读取请求phase
    NGX_HTTP_POST_READ_PHASE = 0,
    //接下来就是开始处理
    //这个阶段主要是处理全局的(server block)的rewrite。
    NGX_HTTP_SERVER_REWRITE_PHASE,
    //这个阶段主要是通过uri来查找对应的location。然后将uri和location的数据关联起来
    NGX_HTTP_FIND_CONFIG_PHASE,
    //这个主要处理location的rewrite。
    NGX_HTTP_REWRITE_PHASE,
    // rewrite,这个主要是进行一些校验以及收尾工作,以便于交给后面的模块。
    NGX_HTTP_POST_REWRITE_PHASE,
    //比如流控这种类型的access就放在这个phase,也就是说它主要是进行一些比较粗粒度的access。
    NGX_HTTP_PREACCESS_PHASE,
    //这个比如存取控制,权限验证就放在这个phase,一般来说处理动作是交给下面的模块做的.这个主要是做一些细粒度的access。
    NGX_HTTP_ACCESS_PHASE,
    //一般来说当上面的access模块得到access_code之后就会由这个模块根据access_code来进行操作
    NGX_HTTP_POST_ACCESS_PHASE,
    //try_file模块,也就是对应配置文件中的try_files指令 todo 此版本还未加入
    //内容处理模块,我们一般的handle都是处于这个模块
    NGX_HTTP_CONTENT_PHASE,
    //log模块
    NGX_HTTP_LOG_PHASE
} ngx_http_phases;

typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;

typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
/**
 * 该结构体是保存在ngx_http_core_main_conf_t的
 * handler链会被转换为ngx_http_phase_handler_s
 * 然后保存在ngx_http_core_main_conf_t的phase_engine中。而后面对handler
 * 的调用处理都是使用ngx_http_phase_handler_s。
 * 这个结构体是每个handler都会有一个的,也就是说所有的phase handler最终都会链接到
 * 一个大的数组中,这个大数组就是ngx_http_phase_engine_t的handlers域。
 */
struct ngx_http_phase_handler_s {
    // checker 所有处于相同phase的handler的check都是相同的,每个phase的handler的调用都是在check中的,
    // 也就是check进行一些校验,结果判断等等操作。
    ngx_http_phase_handler_pt  checker;
    // handler就是对应的handler处理函数
    ngx_http_handler_pt        handler;
    // next 表示了下一个要执行的handler(也就是ngx_http_phase_handler_s)的位置,由于是数组,
    // 所以这个也就表示数组索引。而这个默认就是下一个将要执行的phase
    ngx_uint_t                 next;
};


typedef struct {
    //所有的hanler都会在这个数组中.
    ngx_http_phase_handler_t  *handlers;
    ngx_uint_t                 server_rewrite_index;
} ngx_http_phase_engine_t;


typedef struct {
    //每个phase都会有一个handler数组。
    ngx_array_t                handlers; // 每个handler数组的元素是 ngx_http_handler_pt
} ngx_http_phase_t;


typedef struct {
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */

    ngx_http_phase_engine_t    phase_engine;

    ngx_hash_t                 headers_in_hash;

    ngx_hash_t                 variables_hash;

    ngx_array_t                variables;       /* ngx_http_variable_t */

    ngx_uint_t                 server_names_hash_max_size;
    ngx_uint_t                 server_names_hash_bucket_size;

    ngx_uint_t                 variables_hash_max_size;
    ngx_uint_t                 variables_hash_bucket_size;

    ngx_hash_keys_arrays_t    *variables_keys;

    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1]; // 对应所有http请求的时期
} ngx_http_core_main_conf_t;


typedef struct {
    /*
     * array of the ngx_http_core_loc_conf_t *,
     * used in the ngx_http_core_find_location() and in the merge phase
     */
    ngx_array_t                locations;

    /* array of the ngx_http_listen_t, "listen" directive */
    ngx_array_t                listen;

    /* array of the ngx_http_server_name_t, "server_name" directive */
    ngx_array_t                server_names;

    /* server ctx */
    ngx_http_conf_ctx_t       *ctx;

    ngx_str_t                  server_name;

    size_t                     connection_pool_size;
    size_t                     request_pool_size;
    size_t                     client_header_buffer_size;

    ngx_bufs_t                 large_client_header_buffers;

    ngx_msec_t                 client_header_timeout;

    ngx_flag_t                 optimize_server_names;
    ngx_flag_t                 ignore_invalid_headers;

    ngx_uint_t                 wildcard;  /* unsigned  wildcard:1 */
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
    in_addr_t                  addr;
    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *core_srv_conf;
    ngx_http_virtual_names_t  *virtual_names;
} ngx_http_in_addr_t;


typedef struct {
    in_port_t                  port;
    ngx_str_t                  port_text;
    ngx_http_in_addr_t        *addrs;
    ngx_uint_t                 naddrs;
} ngx_http_in_port_t;


typedef struct {
    in_port_t                  port;
    ngx_array_t                addrs;     /* array of ngx_http_conf_in_addr_t */
} ngx_http_conf_in_port_t;


typedef struct {
    in_addr_t                  addr;

    ngx_hash_t                 hash;
    ngx_hash_wildcard_t        *dns_wildcards;

    ngx_array_t                names;      /* array of ngx_http_server_name_t */

    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *core_srv_conf;

    unsigned                   default_server:1;
    unsigned                   bind:1;

    ngx_http_listen_conf_t    *listen_conf;
} ngx_http_conf_in_addr_t;


typedef struct {
    ngx_str_t                  name;
    ngx_http_core_srv_conf_t  *core_srv_conf; /* virtual name server conf */
} ngx_http_server_name_t;


typedef struct {
    ngx_int_t                  status;
    ngx_int_t                  overwrite;
    ngx_str_t                  uri;
    ngx_array_t               *uri_lengths;
    ngx_array_t               *uri_values;
} ngx_http_err_page_t;


typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;

struct ngx_http_core_loc_conf_s {
    ngx_str_t     name;          /* location name */

#if (NGX_PCRE)
    ngx_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block */

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
    unsigned      alias:1;

    /* array of inclusive ngx_http_core_loc_conf_t */
    ngx_array_t   locations;

    /* pointer to the modules' loc_conf */
    void        **loc_conf ;

    uint32_t      limit_except;
    void        **limit_except_loc_conf ;

    ngx_http_handler_pt  handler;

    ngx_str_t     root;                    /* root, alias */
    ngx_str_t     post_action;

    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;

    off_t         client_max_body_size;    /* client_max_body_size */

    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        limit_rate;              /* limit_rate */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */

    time_t        keepalive_header;        /* keepalive_timeout */

    ngx_flag_t    satisfy_any;             /* satisfy_any */
    ngx_flag_t    internal;                /* internal */
    ngx_flag_t    client_body_in_file_only; /* client_body_in_file_only */
    ngx_flag_t    sendfile;                /* sendfile */
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    ngx_flag_t    log_not_found;           /* log_not_found */
    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */

    ngx_array_t  *error_pages;             /* error_page */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */

    ngx_http_cache_hash_t  *open_files;

    ngx_log_t    *err_log;

    ngx_uint_t    types_hash_max_size;
    ngx_uint_t    types_hash_bucket_size;

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};


void ngx_http_core_run_phases(ngx_http_request_t *r);
ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
ngx_int_t ngx_http_set_exten(ngx_http_request_t *r);
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
    size_t reserved);
ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);

ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_chain_t *out, ngx_uint_t flags);
ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);

ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);


typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);
typedef ngx_int_t (*ngx_http_output_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);


extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;


#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }
                                                                              \
#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0 ;                              \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
