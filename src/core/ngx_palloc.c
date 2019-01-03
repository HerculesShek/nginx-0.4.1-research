
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>

/**
 * 创建一个指定大小的pool
 *
 * @param size 要创建的内存池的大小
 * @param log
 * @return
 */
ngx_pool_t *
ngx_create_pool(size_t size, ngx_log_t *log)
{
    ngx_pool_t  *p;
    // 直接分配size大小的内存
    p = ngx_alloc(size, log);
    if (p == NULL) {
        return NULL;
    }
    // 只能使用 size-sizeof(ngx_pool_t) 的大小
    // 初始化last 指向数据区的开始
    p->last = (u_char *) p + sizeof(ngx_pool_t);
    p->end = (u_char *) p + size;   // end是数据区(和当前内存池的)结束位置
    p->current = p;                 // 创建新的内存池的时候 第一个是链表的头 current表示这个内存池链表中第一个可以申请数据区的几诶但 初次创建时便指向当前的内存池
    p->chain = NULL;
    p->next = NULL;
    p->large = NULL;
    p->cleanup = NULL;
    p->log = log;

    return p;
}

/**
 * 销毁内存池
 *
 * @param pool
 */
void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_t          *p, *n;
    ngx_pool_large_t    *l;
    ngx_pool_cleanup_t  *c;

    // 调用清理函数
    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            c->handler(c->data);
        }
    }

    // 遍历free掉大块
    for (l = pool->large; l; l = l->next) {

        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);

        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

#if (NGX_DEBUG)

    /*
     * we could allocate the pool->log from this pool
     * so we can not use this log while the free()ing the pool
     */

    for (p = pool, n = pool->next; /* void */; p = n, n = n->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                       "free: %p, unused: %uz", p, p->end - p->last);

        if (n == NULL) {
            break;
        }
    }

#endif
    // 把所有的内存池处理掉
    for (p = pool, n = pool->next; /* void */; p = n, n = n->next) {
        ngx_free(p);

        if (n == NULL) {
            break;
        }
    }

    // todo will 在nginx中内存池中的小块数据是从来不释放???
}


/**
 * 我要在pool中占用size的空间 然后把这个内存指针给我
 *
 * @param pool 要在这个pool中占用空间
 * @param size 使用的空间大小
 * @return
 */
void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    u_char            *m;
    ngx_pool_t        *p, *n;
    ngx_pool_large_t  *large;

    /*
     * todo will 应该在pool中持有一个size变量 提供当前pool可用空间 超过则使用大内存块 以下if判断是相同的逻辑
     * 在pool中要使用的内存：
     *  1 要小于 NGX_MAX_ALLOC_FROM_POOL 就是：页大小-1
     *  2 要小于pool中数据空间大小 (pool->end - (u_char *) pool) 当前poll中总空间大小
     *      ngx_align_ptr(sizeof(ngx_pool_t), NGX_ALIGNMENT) 则是ngx_pool_t元信息指针对齐后的占用的空间
     *      两者相减即是数据空间的大小
     *
     *  新的ngx_pool_t结构中记录一个当前内存池数据区的最大值 即是 NGX_MAX_ALLOC_FROM_POOL 和
     *  (size_t) (pool->end - (u_char *) pool) - (size_t) ngx_align_ptr(sizeof(ngx_pool_t), NGX_ALIGNMENT)
     *  中的较小值
     *  用此内存池数据区的最大值的最为是否建立大块内存的条件 以下判断逻辑相同
     */
    if (size <= (size_t) NGX_MAX_ALLOC_FROM_POOL
        && size <= (size_t) (pool->end - (u_char *) pool)
                   - (size_t) ngx_align_ptr(sizeof(ngx_pool_t), NGX_ALIGNMENT))
    {
        for (p = pool->current; /* void */ ; p = p->next) { // 遍历内存池

            // todo 如果size是0、1、2、3 或者是大于4的奇数？？？
            // 我觉得可以直接执行else中的语句即可 对齐last指针就行了
            if (size < sizeof(int) || (size & 1)) {
                m = p->last;

            } else {
                m = ngx_align_ptr(p->last, NGX_ALIGNMENT);
            }

            // 计算当前内存池节点的可用空间大小 够用则更新last之后 直接返回
            if ((size_t) (p->end - m) >= size) {
                p->last = m + size;

                return m;
            }

            // 当前剩余空间太小 连一个对齐的宽度都不够 则将current指向下一个
            // 这说明current代表当前可用的内存池
            if ((size_t) (p->end - m) < NGX_ALIGNMENT) {
                pool->current = p->next;
            }

            if (p->next == NULL) {
                break;
            }
        }

        /* allocate a new pool block */
        // 新分配的内存池和pool链的最后一个内存池一样大
        n = ngx_create_pool((size_t) (p->end - (u_char *) p), p->log);
        if (n == NULL) {
            return NULL;
        }

        if (pool->current == NULL) {
            pool->current = n;
        }

        p->next = n;
        m = ngx_align_ptr(n->last, NGX_ALIGNMENT);
        n->last = m + size;

        return m;
    }

#if 0
    p = ngx_memalign(ngx_pagesize, size, pool->log);
    if (p == NULL) {
        return NULL;
    }
#else
    p = ngx_alloc(size, pool->log);
    if (p == NULL) {
        return NULL;
    }
#endif

    // 理论上来说 新建内存池的数据空间部分必须要大于sizeof(ngx_pool_large_t)的 否则死循环了 (虽然不可能这么申请内存空间)
    // 比如 如果这么调用：
    //    size_t size = sizeof(ngx_pool_t) + sizeof(ngx_pool_large_t) - 2;
    //    ngx_pool_t *p = ngx_create_pool(size);
    //    ngx_pool_large_t *pool_large = ngx_palloc(p, sizeof(ngx_pool_large_t));
    // 则必然陷入死循环
    // 所以这个函数bug比较严重 并且抽象和设计不够
    large = ngx_palloc(pool, sizeof(ngx_pool_large_t));
    if (large == NULL) {
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


ngx_int_t
ngx_pfree(ngx_pool_t *pool, void *p)
{
    ngx_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "free: %p", l->alloc);
            ngx_free(l->alloc);
            l->alloc = NULL;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    p = ngx_palloc(pool, size);
    if (p) {
        ngx_memzero(p, size); // 申请的内存内容置为0
    }

    return p;
}


void *
ngx_shalloc(size_t size)
{
    u_char  *p;

    if (size < sizeof(int) || (size & 1)) {
        p = ngx_cycle->shm_last;

    } else {
        p = ngx_align_ptr(ngx_cycle->shm_last, NGX_ALIGNMENT);
    }

    if ((size_t) (ngx_cycle->shm_end - p) >= size) {
        ngx_cycle->shm_last = p + size;
        return p;
    }

    ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                  "allocation of %uz bytes in shared memory failed, "
                  "only %uz are available",
                  size, ngx_cycle->shm_end - ngx_cycle->shm_last);

    return NULL;
}


void *
ngx_shcalloc(size_t size)
{
    void *p;

    p = ngx_shalloc(size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}

/**
 * 为内存池p添加清理函数的结构 函数还没有指定
 *
 * @param p
 * @param size 这个清理函数接受的数据的大小
 * @return
 */
ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *p, size_t size)
{
    ngx_pool_cleanup_t  *c;

    c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = ngx_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = p->cleanup; // 将这个放在清理函数链的头部

    p->cleanup = c;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}


void
ngx_pool_cleanup_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, c->log, 0, "run cleanup: %p, fd:%d",
                   c, c->fd);

    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


#if 0

static void *
ngx_get_cached_block(size_t size)
{
    void                     *p;
    ngx_cached_block_slot_t  *slot;

    if (ngx_cycle->cache == NULL) {
        return NULL;
    }

    slot = &ngx_cycle->cache[(size + ngx_pagesize - 1) / ngx_pagesize];

    slot->tries++;

    if (slot->number) {
        p = slot->block;
        slot->block = slot->block->next;
        slot->number--;
        return p;
    }

    return NULL;
}

#endif
