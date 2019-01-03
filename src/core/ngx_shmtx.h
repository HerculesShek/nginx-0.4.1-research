
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/**
 * nginx中锁的机制
 * 如果支持原子操作 则使用mmap
 * 否则则使用文件句柄
 */
typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
    ngx_atomic_t  *lock;
#else
    ngx_fd_t       fd;
    u_char        *name;
    ngx_log_t     *log;
#endif
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr, u_char *name,
    ngx_log_t *log);


#if (NGX_HAVE_ATOMIC_OPS)
// 这种static inline的函数 可以在头文件中定义
/**
 * 获取锁 非阻塞的 获取不到则直接返回
 * 首先判断lock是否为0,为0的话则调用ngx_atomic_cmp_set去获得锁,
 * 如果获得成功就会返回1,否则为0.
 * @param mtx
 * @return
 */
static ngx_inline ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    // ngx_atomic_cmp_set意思就是如果lock的值是0的话,就把lock的值修改为当前的进程id,否则返回失败。
    if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
        return 1;
    }

    return 0;
}

#define ngx_shmtx_lock(mtx)   ngx_spinlock((mtx)->lock, ngx_pid, 1024)

#define ngx_shmtx_unlock(mtx) (void) ngx_atomic_cmp_set((mtx)->lock, ngx_pid, 0)

#define ngx_shmtx_destory(mtx)


#else

static ngx_inline ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_trylock_fd(mtx->fd);

    if (err == 0) {
        return 1;
    }

    if (err == NGX_EAGAIN) {
        return 0;
    }

    ngx_log_error(NGX_LOG_ALERT, mtx->log, err, ngx_trylock_fd_n " failed");

    ngx_abort();
}


static ngx_inline void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_error(NGX_LOG_ALERT, mtx->log, err, ngx_lock_fd_n " failed");

    ngx_abort();
}


static ngx_inline void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_error(NGX_LOG_ALERT, mtx->log, err, ngx_unlock_fd_n " failed");

    ngx_abort();
}


void ngx_shmtx_destory(ngx_shmtx_t *mtx);

#endif


#endif /* _NGX_SHMTX_H_INCLUDED_ */
