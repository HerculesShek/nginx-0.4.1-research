
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_SHARED_H_INCLUDED_
#define _NGX_SHARED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/**
 * 进程间共享内存
 */
typedef struct {
    u_char      *addr;
    size_t       size;
    ngx_log_t   *log;
} ngx_shm_t;


ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
void ngx_shm_free(ngx_shm_t *shm);


#endif /* _NGX_SHARED_H_INCLUDED_ */
