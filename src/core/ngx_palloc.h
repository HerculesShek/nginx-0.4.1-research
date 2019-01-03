
/*
 * Copyright (C) Igor Sysoev
 * nginx pool allocation
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On FreeBSD 5.x it allows to use the zero copy sending.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE   (16 * 1024)


typedef void (*ngx_pool_cleanup_pt)(void *data); /* 清理内存池中数据的handler */

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;  // 清理函数
    void                 *data;     // 传递给清理函数的数据
    ngx_pool_cleanup_t   *next;     // 下一个清理函数
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

// 用于申请大块内存
struct ngx_pool_large_s {
    ngx_pool_large_t     *next;   /* 下一个大内存块 */
    void                 *alloc;  /* 数据区 */
};

/*
 * 0.4.1版本的内存池结构 其中好几个变量和函数还没有使用
 * todo will 说明此版本的内存池设计还不完善
 *
 */
struct ngx_pool_s { // 实现了一个链表结构
    /**
     * last end和next构成了当前内存池的数据层(与数据相关)
     * 如果当前内存池已经满了，一般是扩大内存池，但是nginx不是，而是重新分配一块新的内存池
     * next便指向新的内存池
     */
    u_char               *last;    // 表示数据区当前已经使用的数据的结尾，也就意味着要分配的新数据的开始
    u_char               *end;     // 当前内存池的数据结尾 end-last 就是当前内存池的可用空间
    ngx_pool_t           *next;    // 下一块内存池

    ngx_pool_t           *current; // 指向当前内存池(链)中第一个可以分配空间的内存池
    ngx_chain_t          *chain;   // 将所有的内存池都链接起来 与buffer相关 (它会创建多个内存池)

    ngx_pool_large_t     *large;   // 单链表 表示大的数据块
    ngx_pool_cleanup_t   *cleanup; // 清理函数链表
    ngx_log_t            *log;
};


typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;



//void *ngx_alloc(size_t size, ngx_log_t *log);
//void *ngx_calloc(size_t size, ngx_log_t *log);

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);

void *ngx_shalloc(size_t size);
void *ngx_shcalloc(size_t size);
void ngx_shfree(void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_cleanup_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
