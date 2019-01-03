
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

/**
 * 一般先把数据放入buf中 然后当设备或者socket准备好了 就会从buf中读取 这里的pos就是buf中已经读取的数据位置
 */
struct ngx_buf_s {
    u_char          *pos;       // 已经执行的数据位置
    u_char          *last;      // 和ngx_pool中的last一样 使用的内存的最后一个字节的指针
    off_t            file_pos;  ///文件指针
    off_t            file_last; //

    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */


    ngx_buf_tag_t    tag;       //// 这个buf从属于哪个模块
    ngx_file_t      *file;      //
    ngx_buf_t       *shadow;    // todo 为何有个影子？


    /* the buf's content could be changed 内容可以改变*/
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     * 在内存cache中或者是只读内存中时不能改变
     */
    unsigned         memory:1;

    /* the buf's content is mmap()ed and must not be changed
     * 内容是mmap()的 并且不能改变的 */
    unsigned         mmap:1;

    unsigned         recycled:1;
    unsigned         in_file:1; ///是否文件。
    unsigned         flush:1;
    unsigned         sync:1;
    unsigned         last_buf:1;
    unsigned         last_in_chain:1;

    unsigned         last_shadow:1;
    unsigned         temp_file:1;

    unsigned         zerocopy_busy:1;

    /* STUB */ int   num;
};

// 就是一个单链表 将buf串起来
struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

/**
 * 这个chain主要是管理输出buf 作为ngx_chain输出的上下文
 * 包含了三种类型的chain,分别是in,free以及busy
 *
 * 它对应的主要是ngx_output_chain函数。这个函数主要功能就是拷贝in chain的数据到buf域中
 * 这个函数很复杂
 */
typedef struct {
    ngx_buf_t                   *buf;   // 这个域也就是我们拷贝数据的地方,我们一般输出的话都是从in直接copy相应的size到buf中。
    ngx_chain_t                 *in;    // 这个就是我们保存那些需要发送数据的地方
    ngx_chain_t                 *free;  // 这个保存了一些空的buf,也就是说如果free存在,我们都会直接从free中取buf到前面的buf域
    ngx_chain_t                 *busy;  // 这个保存了已经发送完毕的buf,也就是每次我们从in中将buf读取完毕后,确定数据已经取完,此时就会将这个chain拷贝到busy中。然后将比较老的busy buf拷贝到free中。

    ///相关的标记,是否使用sendfile,是否可以操作内存数据，是否使用directio等等
    unsigned                     sendfile;
    unsigned                     need_in_memory;
    unsigned                     need_in_temp;

    ///内存池。
    ngx_pool_t                  *pool;
    ///每次从pool中重新alloc一个buf这个值都会相应加一。
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ///这个用来标记当前那个模块使用这个chain
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter; // output_filter是一个回调函数,用来过滤输出。
    void                        *filter_ctx; // 传递给output_filter的数据
} ngx_output_chain_ctx_t;


/**
 * 这个主要是用在upstream模块
 * 这里我们要知道out是会变化的。每次输出后,这个都会指向下一个需要发送的chain。
 */
typedef struct {
    ngx_chain_t                 *out;  ///保存了所要输出的chain
    ngx_chain_t                **last; ///这个保存了这次新加入的所需要输出的chain。
    ngx_connection_t            *connection; ///这个表示当前连接
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
#define ngx_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag);


#endif /* _NGX_BUF_H_INCLUDED_ */
