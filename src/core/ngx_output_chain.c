
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if 0
#define NGX_SENDFILE_LIMIT  4096
#endif


#define NGX_NONE            1


static ngx_inline ngx_int_t
    ngx_output_chain_need_to_copy(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf);
static ngx_int_t ngx_output_chain_add_copy(ngx_pool_t *pool,
    ngx_chain_t **chain, ngx_chain_t *in);
static ngx_int_t ngx_output_chain_copy_buf(ngx_buf_t *dst, ngx_buf_t *src,
    ngx_uint_t sendfile);


/**
 * 拷贝in chain的数据到buf域中
 *
 * @param ctx
 * @param in
 * @return
 */
ngx_int_t
ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in)
{
    off_t         bsize;
    size_t        size;
    ngx_int_t     rc, last;
    ngx_uint_t    recycled;
    ngx_chain_t  *cl, *out, **last_out;

    if (ctx->in == NULL && ctx->busy == NULL) {

        /*
         * the short path for the case when the ctx->in and ctx->busy chains
         * are empty, the incoming chain is empty too or has the single buf
         * that does not require the copy
         */

        if (in == NULL) { // the incoming chain is empty too
            return ctx->output_filter(ctx->filter_ctx, in);
        }

        // the incoming chain has the single buf
        if (in->next == NULL
#if (NGX_SENDFILE_LIMIT)
            && !(in->buf->in_file && in->buf->file_last > NGX_SENDFILE_LIMIT)
#endif
            && !ngx_output_chain_need_to_copy(ctx, in->buf))
        {
            return ctx->output_filter(ctx->filter_ctx, in);
        }
    }

    /* add the incoming buf to the chain ctx->in */
    ///拷贝in 到ctx的in chain中。
    if (in) {
        if (ngx_output_chain_add_copy(ctx->pool, &ctx->in, in) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    out = NULL;
    last_out = &out;
    last = NGX_NONE;

    ///开始循环处理ctx-in chain.这里有两层循环。
    for ( ;; ) {
        ///开始遍历in
        while (ctx->in) {

            /*
             * cycle while there are the ctx->in bufs
             * or there are the free output bufs to copy in
             */
            ///计算当前in的buf长度。这个长度也就是还没处理的数据长度。
            bsize = ngx_buf_size(ctx->in->buf);

            if (bsize == 0 && !ngx_buf_special(ctx->in->buf)) {

                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                              "zero size buf in output "
                              "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                              ctx->in->buf->temporary,
                              ctx->in->buf->recycled,
                              ctx->in->buf->in_file,
                              ctx->in->buf->start,
                              ctx->in->buf->pos,
                              ctx->in->buf->last,
                              ctx->in->buf->file,
                              ctx->in->buf->file_pos,
                              ctx->in->buf->file_last);

                ngx_debug_point();

                ctx->in = ctx->in->next;

                continue;
            }

            if (!ngx_output_chain_need_to_copy(ctx, ctx->in->buf)) {

                /* move the chain link to the output chain */

                cl = ctx->in;
                ctx->in = cl->next;

                *last_out = cl;
                last_out = &cl->next;
                cl->next = NULL;

                continue;
            }

            ///如果buf为空,则我们需要给buf分配空间。
            ///这里主要是处理file buf,如果是file buf则会create一个buf链接到ctx
            if (ctx->buf == NULL) {

                /* get the free buf */

                if (ctx->free) {///如果free不为空,则我们从free chain中取得buf。
                    cl = ctx->free;
                    ctx->buf = cl->buf;
                    ctx->free = cl->next;
                    ngx_free_chain(ctx->pool, cl);

                } else if (out || ctx->allocated == ctx->bufs.num) {

                    break;

                } else {
                    ///否则我们要重新create一个buf,然后链接到ctx,这里主要buf的大小和in chain的没有处理的数据一样大。

                    size = ctx->bufs.size;
                    recycled = 1;

                    if (ctx->in->buf->last_in_chain) {

                        if (bsize < (off_t) ctx->bufs.size) {

                           /*
                            * allocate small temp buf for the small last buf
                            * or its small last part
                            */

                            size = (size_t) bsize;
                            recycled = 0;

                        } else if (ctx->bufs.num == 1
                                   && (bsize < (off_t) (ctx->bufs.size
                                                     + (ctx->bufs.size >> 2))))
                        {
                            /*
                             * allocate a temp buf that equals
                             * to the last buf if the last buf size is lesser
                             * than 1.25 of bufs.size and a temp buf is single
                             */

                            size = (size_t) bsize;
                            recycled = 0;
                        }
                    }

                    ctx->buf = ngx_create_temp_buf(ctx->pool, size);
                    if (ctx->buf == NULL) {
                        return NGX_ERROR;
                    }

                    ctx->buf->tag = ctx->tag;
                    ctx->buf->recycled = recycled;
                    ctx->allocated++;
                }
            }
            ///从in chain拷贝数据到buf,并更新相关域。
            rc = ngx_output_chain_copy_buf(ctx->buf, ctx->in->buf,
                                           ctx->sendfile);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (rc == NGX_AGAIN) {
                if (out) {
                    break;
                }

                return rc;
            }

            /* delete the completed buf from the ctx->in chain */

            ///如果size为0,说明in chain中的第一个chain的数据已经被拷贝完了,此时删除这个chain。
            if (ngx_buf_size(ctx->in->buf) == 0) {
                ctx->in = ctx->in->next;
            }

            ///重新分配一个 chain
            cl = ngx_alloc_chain_link(ctx->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            ///链接buf到cl
            cl->buf = ctx->buf;
            cl->next = NULL;
            *last_out = cl;
            last_out = &cl->next;
            ctx->buf = NULL;
        }

        if (out == NULL && last != NGX_NONE) {

            if (ctx->in) {
                return NGX_AGAIN;
            }

            return last;
        }

        ///调用回调函数
        last = ctx->output_filter(ctx->filter_ctx, out);

        if (last == NGX_ERROR || last == NGX_DONE) {
            return last;
        }
        ///update 相关的chain,主要是将刚才copy完的buf 加入到busy chain,然后从busy chain中取出buf放到free chain中。
        ngx_chain_update_chains(&ctx->free, &ctx->busy, &out, ctx->tag);
        last_out = &out;
    }
}


static ngx_inline ngx_int_t
ngx_output_chain_need_to_copy(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf)
{
    ngx_uint_t  sendfile;

    if (ngx_buf_special(buf)) {
        return 0;
    }

    sendfile = ctx->sendfile;

#if (NGX_SENDFILE_LIMIT)

    if (buf->in_file && buf->file_pos >= NGX_SENDFILE_LIMIT) {
        sendfile = 0;
    }

#endif

    if (!sendfile) {

        if (!ngx_buf_in_memory(buf)) {
            return 1;
        }

        buf->in_file = 0;
    }

    if (ctx->need_in_memory && !ngx_buf_in_memory(buf)) {
        return 1;
    }

    if (ctx->need_in_temp && (buf->memory || buf->mmap)) {
        return 1;
    }

    return 0;
}


static ngx_int_t
ngx_output_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;
#if (NGX_SENDFILE_LIMIT)
    ngx_buf_t    *b, *buf;
#endif

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {

        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

#if (NGX_SENDFILE_LIMIT)

        buf = in->buf;

        if (buf->in_file
            && buf->file_pos < NGX_SENDFILE_LIMIT
            && buf->file_last > NGX_SENDFILE_LIMIT)
        {
            b = ngx_calloc_buf(pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, buf, sizeof(ngx_buf_t));

            if (ngx_buf_in_memory(buf)) {
                buf->pos += (ssize_t) (NGX_SENDFILE_LIMIT - buf->file_pos);
                b->last = buf->pos;
            }

            buf->file_pos = NGX_SENDFILE_LIMIT;
            b->file_last = NGX_SENDFILE_LIMIT;

            cl->buf = b;

        } else {
            cl->buf = buf;
            in = in->next;
        }

#else
        cl->buf = in->buf;
        in = in->next;

#endif

        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_output_chain_copy_buf(ngx_buf_t *dst, ngx_buf_t *src, ngx_uint_t sendfile)
{
    off_t    size;
    ssize_t  n;

    size = ngx_buf_size(src);

    if (size > dst->end - dst->pos) {
        size = dst->end - dst->pos;
    }

#if (NGX_SENDFILE_LIMIT)

    if (src->in_file && src->file_pos >= NGX_SENDFILE_LIMIT) {
        sendfile = 0;
    }

#endif

    if (ngx_buf_in_memory(src)) {
        ngx_memcpy(dst->pos, src->pos, (size_t) size);
        src->pos += (size_t) size;
        dst->last += (size_t) size;

        if (src->in_file) {

            if (sendfile) {
                dst->in_file = 1;
                dst->file = src->file;
                dst->file_pos = src->file_pos;
                dst->file_last = src->file_pos + size;

            } else {
                dst->in_file = 0;
            }

            src->file_pos += size;

        } else {
            dst->in_file = 0;
        }

        if (src->last_buf && src->pos == src->last) {
            dst->last_buf = 1;
        }

    } else {
        n = ngx_read_file(src->file, dst->pos, (size_t) size, src->file_pos);

        if (n == NGX_ERROR) {
            return (ngx_int_t) n;
        }

#if (NGX_FILE_AIO_READ)
        if (n == NGX_AGAIN) {
            return (ngx_int_t) n;
        }
#endif

        if (n != size) {
            ngx_log_error(NGX_LOG_ALERT, src->file->log, 0,
                          ngx_read_file_n " reads only %z of %O from file",
                          n, size);
            if (n == 0) {
                return NGX_ERROR;
            }
        }

        dst->last += n;

        if (sendfile) {
            dst->in_file = 1;
            dst->file = src->file;
            dst->file_pos = src->file_pos;
            dst->file_last = src->file_pos + n;

        } else {
            dst->in_file = 0;
        }

        src->file_pos += n;

        if (src->last_buf && src->file_pos == src->file_last) {
            dst->last_buf = 1;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_chain_writer(void *data, ngx_chain_t *in)
{
    ngx_chain_writer_ctx_t *ctx = data;

    off_t         size;
    ngx_chain_t  *cl;

    ///这里将in中的也就是新加入的chain ,全部复制到last中。也就是它保存了最后的数据。
    for (size = 0; in; in = in->next) {

#if 1
        if (ngx_buf_size(in->buf) == 0 && !ngx_buf_special(in->buf)) {
            ngx_debug_point();
        }
#endif
        ///计算大小
        size += ngx_buf_size(in->buf);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->connection->log, 0,
                       "chain writer buf size: %uz", ngx_buf_size(in->buf));

        cl = ngx_alloc_chain_link(ctx->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        ///加入last
        cl->buf = in->buf;
        cl->next = NULL;
        *ctx->last = cl;
        ctx->last = &cl->next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->connection->log, 0,
                   "chain writer in: %p", ctx->out);

    ///遍历out chain
    for (cl = ctx->out; cl; cl = cl->next) {

#if 1
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_debug_point();
        }

#endif
        ///计算所需要输出的大小
        size += ngx_buf_size(cl->buf);
    }

    if (size == 0) {
        return NGX_OK;
    }

    ///调用send_chain(一般是writev)来输出out中的数据。
    ctx->out = ctx->connection->send_chain(ctx->connection, ctx->out,
                                           ctx->limit);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->connection->log, 0,
                   "chain writer out: %p", ctx->out);

    if (ctx->out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    if (ctx->out == NULL) {
        ctx->last = &ctx->out;
        return NGX_OK;
    }

    return NGX_AGAIN;
}
