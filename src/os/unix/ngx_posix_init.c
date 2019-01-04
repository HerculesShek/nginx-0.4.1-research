
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>


ngx_int_t   ngx_ncpu; // cpu核数
ngx_int_t   ngx_max_sockets;
ngx_uint_t  ngx_inherited_nonblocking;
ngx_uint_t  ngx_tcp_nodelay_and_tcp_nopush;


struct rlimit  rlmt;

/**
 * 负责手法信息的函数指针
 */
ngx_os_io_t ngx_os_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    NULL,
    ngx_writev_chain,
    0
};

/**
 * 操作系统相关变量初始化
 * 设置进程名字
 * 设置页大小 4096
 * 设置cpu缓存位宽 64
 * 设置cpu核数
 *
 * @param log
 * @return
 */
ngx_int_t
ngx_os_init(ngx_log_t *log)
{
    // NGX_HAVE_OS_SPECIFIC_INIT is 1
#if (NGX_HAVE_OS_SPECIFIC_INIT)
    if (ngx_os_specific_init(log) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    ngx_init_setproctitle(log);

    ngx_pagesize = getpagesize();
    ngx_cacheline_size = NGX_CPU_CACHE_LINE;

    // todo will 貌似没有真正设置正确cpu核数
    if (ngx_ncpu == 0) {
        ngx_ncpu = 1;
    }

    ngx_cpuinfo();

    // 获取系统限制的可以打开的最大文件数量 centos7中是4096
    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed)");
        return NGX_ERROR;
    }

    // 设置最大连接数 1024
    ngx_max_sockets = (ngx_int_t) rlmt.rlim_cur;

#if (NGX_HAVE_INHERITED_NONBLOCK)
    ngx_inherited_nonblocking = 1;
#else
    ngx_inherited_nonblocking = 0;
#endif

    return NGX_OK;
}


void
ngx_os_status(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_NOTICE, log, 0, NGINX_VER);

#ifdef NGX_COMPILER
    ngx_log_error(NGX_LOG_NOTICE, log, 0, "built by " NGX_COMPILER);
#endif

#if (NGX_HAVE_OS_SPECIFIC_INIT)
    ngx_os_specific_status(log);
#endif

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "getrlimit(RLIMIT_NOFILE): %r:%r",
                  rlmt.rlim_cur, rlmt.rlim_max);
}


ngx_int_t
ngx_posix_post_conf_init(ngx_log_t *log)
{
    ngx_fd_t  pp[2];

    if (pipe(pp) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "pipe() failed");
        return NGX_ERROR;
    }

    if (dup2(pp[1], STDERR_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, errno, "dup2(STDERR) failed");
        return NGX_ERROR;
    }

    if (pp[1] > STDERR_FILENO) {
        if (close(pp[1]) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, errno, "close() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
