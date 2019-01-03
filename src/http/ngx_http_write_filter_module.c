
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_write_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_write_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_write_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_write_filter_module_ctx,     /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};



ngx_int_t
ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                      size, sent, to_send;
    ngx_uint_t                 last, flush;
    ngx_chain_t               *cl, *ln, **ll, *chain;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    //得到当前所属的连接
    c = r->connection;

    if (c->error) {
        return NGX_ERROR;
    }

    size = 0;
    flush = 0;
    last = 0;
    //得到上次没有发送完毕的chain
    ll = &r->out;

    /* find the size, the flush point and the last link of the saved chain */
    // 然后接下来这部分是校验并统计out chain,也就是上次没有完成的chain buf。
    for (cl = r->out; cl; cl = cl->next) {
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %z",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        //如果有0长度的buf则返回错误。
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif
        //得到buf的大小
        size += ngx_buf_size(cl->buf);
        //看当传输完毕后是否要刷新buf。
        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }
        //看是否是最后一个buf
        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */
    // 接下来这部分是用来链接新的chain到上面的out chain后面

    for (ln = in; ln; ln = ln->next) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ln->buf;
        //前面的代码我们知道ll已经指向out chain的最后一个位置了,因此这里就是将新的chain链接到out chain的后面。
        *ll = cl;
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %z",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        //校验buf
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();
            return NGX_ERROR;
        }
#endif
        //计算大小
        size += ngx_buf_size(cl->buf);

        //判断是否需要flush
        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        //判断是否是最后一个buf
        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    // 然后接下来的这段代码主要是对进行发送前buf的一些标记的处理。

    /**
    在看代码之前先来解释下几个比较重要的标记。

    第一个是ngx_http_core_module的conf的一个标记postpone_output(conf里面可以配置的),这个表示延迟
    输出的阀,也就是说将要发送的字节数如果小于这个的话,并且还有另外几个条件的话(下面会解释),就会直接返
    回不发送当前的chain。

    第二个是c->write->delayed,这个表示当前的连接的写必须要被delay了,也就是说现在不能发送了(原因下面
    会解释),得等另外的地方取消了delayed才能发送,此时我们修改连接的buffered的标记,然后返回
    NGX_AGAIN.

    第三个是c->buffered,因为有时buf并没有发完,因此我们有时就会设置buffed标记,而我们可能会在多个
    filter模块中被buffered,因此下面就是buffered的类型。

    然后我们来看第二个的意思,这个表示当前的chain已经被buffered了,

    第四个是r->limit_rate,这个表示当前的request的发送限制速率,这个也是在nginx.conf中配置的,而一般就
    是通过这个值来设置c->write->delayed的。也就是说如果发送速率大于这个limit了的话,就设置delayed,然
    后这边的request就会延迟发送,下面我们的代码会看到nginx如何处理。
     */
    *ll = NULL;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%d f:%d s:%O", last, flush, size);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

    //也就是说将要发送的字节数小于postpone_output并且不是最后一个buf,并且不需要刷新chain的话,就直接返回。
    if (!last && !flush && in && size < (off_t) clcf->postpone_output) {
        return NGX_OK;
    }

    ///如果设置了write的delayed,则设置标记。
    if (c->write->delayed) {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    //如果size为0,并且没有设置buffered标记,则进入清理工作。
    if (size == 0 && !(c->buffered & NGX_LOWLEVEL_BUFFERED)) {
        //如果是最后一个buf,则清理buffered标记然后清理out chain
        if (last) {
            r->out = NULL;
            c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

            return NGX_OK;
        }
        //如果有设置flush的话,则会强行传输当前buf之前的所有buf,因此这里就需要清理out chain。
        if (flush) {
            do {
                r->out = r->out->next;
            } while (r->out);

            //清理buf 标记
            c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "the http output chain is empty");

        ngx_debug_point();

        return NGX_ERROR;
    }

    //如果有发送速率限制。
    if (r->limit_rate) {
        //计算是否有超过速率限制
        to_send = r->limit_rate * (ngx_time() - r->start_time + 1) - c->sent;

        //如果有
        if (to_send <= 0) {
            //设置delayed标记
            c->write->delayed = 1;
            //设置定时器
            ngx_add_timer(c->write,
                          (ngx_msec_t) (- to_send * 1000 / r->limit_rate + 1));
            //设置buffered。
            c->buffered |= NGX_HTTP_WRITE_BUFFERED;

            return NGX_AGAIN;
        }

    } else {
        to_send = 0;
    }

    //然后接下来这段就是发送buf,以及发送完的处理部分。这里要注意send_chain返回值为还没有发送完的
    //chain,这个函数我后面的blog会详细的分析的。
    sent = c->sent;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter to send %O", to_send);

    //调用发送函数。
    chain = c->send_chain(c, r->out, to_send);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

    if (chain == NGX_CHAIN_ERROR) {
        c->error = 1;
        return NGX_ERROR;
    }

    //控制imit_rate,这个值一般是在nginx.conf中配置的。
    if (to_send) {
        sent = c->sent - sent;
        c->write->delayed = 1;
        ngx_add_timer(c->write, (ngx_msec_t) (sent * 1000 / r->limit_rate + 1));
    }

    //开始遍历上一次还没有传输完毕的chain,如果这次没有传完的里面还有的话,就跳出循环,否则free这个chain
    for (cl = r->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    ///out chain赋值
    r->out = chain;

    //如果chain存在,则设置buffered并且返回again。
    if (chain) {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    //否则清理buffered
    c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

    //如果有其他的filter buffered并且postponed被设置了,则我们返回again,也就是还有buf要处理。
    if ((c->buffered & NGX_LOWLEVEL_BUFFERED) && r->postponed == NULL) {
        return NGX_AGAIN;
    }

    //否则返回ok
    return NGX_OK;
}


static ngx_int_t
ngx_http_write_filter_init(ngx_conf_t *cf)
{
    ngx_http_top_body_filter = ngx_http_write_filter;

    return NGX_OK;
}
