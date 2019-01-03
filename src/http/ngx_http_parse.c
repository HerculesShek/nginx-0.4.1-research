
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* gcc, icc, msvc and others compile these switches as an jump table */

/**
 * well well well 这就是个状态机！
 *
 * @param r
 * @param b
 * @return
 */
ngx_int_t
ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b)
{
    u_char  c, ch, *p, *m;
    enum {
        sw_start = 0,
        sw_method,
        sw_space_after_method,
        sw_spaces_before_uri,
        sw_schema,
        sw_schema_slash,
        sw_schema_slash_slash,
        sw_host,
        sw_port,
        sw_after_slash_in_uri,
        sw_check_uri,
        sw_uri,
        sw_http_09,
        sw_http_H,
        sw_http_HT,
        sw_http_HTT,
        sw_http_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_almost_done
    } state;

    state = r->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* HTTP methods: GET, HEAD, POST */
        case sw_start:
            r->request_start = p;

            //如果是回车换行则跳出switch,然后继续解析
            if (ch == CR || ch == LF) {
                break;
            }

            //不是A到Z的字母(大小写敏感的),并且不是_则返回错误
            if (ch < 'A' || ch > 'Z') {
                return NGX_HTTP_PARSE_INVALID_METHOD;
            }

            //到达这里说明下一步改解析方法了。因此下一个状态就是method
            state = sw_method;
            break;

        case sw_method:
            //如果再次读到空格则说明我们已经准备解析request-URL,此时我们就能得到请求方法了
            if (ch == ' ') {
                //先得到method的结束位置
                r->method_end = p - 1;
                m = r->request_start;

                //得到方法的长度,通过长度来得到具体不同的方法,然后给request的method赋值。
                switch (p - m) {

                case 3:
                    if (m[0] == 'G' && m[1] == 'E' && m[2] == 'T') {
                        r->method = NGX_HTTP_GET;

                    } else if (m[0] == 'P' && m[1] == 'U' && m[2] == 'T') {
                        r->method = NGX_HTTP_PUT;
                    }
                    break;

                case 4:
                    if (m[0] == 'P' && m[1] == 'O'
                        && m[2] == 'S' && m[3] == 'T')
                    {
                        r->method = NGX_HTTP_POST;

                    } else if (m[0] == 'H' && m[1] == 'E'
                               && m[2] == 'A' && m[3] == 'D')
                    {
                        r->method = NGX_HTTP_HEAD;
                    }
                    break;

                case 5:
                    if (m[0] == 'M' && m[1] == 'K'
                        && m[2] == 'C' && m[3] == 'O' && m[4] == 'L')
                    {
                        r->method = NGX_HTTP_MKCOL;
                    }
                    break;

                case 6:
                    if (m[0] == 'D' && m[1] == 'E' && m[2] == 'L'
                        && m[3] == 'E' && m[4] == 'T' && m[5] == 'E')
                    {
                        r->method = NGX_HTTP_DELETE;
                    }
                    break;
                }

                //下一个状态准备开始解析URI
                state = sw_spaces_before_uri;
                break;
            }

            if (ch < 'A' || ch > 'Z') {
                return NGX_HTTP_PARSE_INVALID_METHOD;
            }

            break;

        /* single space after method */
        case sw_space_after_method:
            switch (ch) {
            case ' ':
                state = sw_spaces_before_uri;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_METHOD;
            }
            break;

        /* space* before URI */
        //然后是sw_spaces_before_uri状态,这里由于uri会有两种情况,一种是带schema的,一种是直接相对路径的
        //(可以看前面的uri格式).
        case sw_spaces_before_uri:

            c = (u_char) (ch | 0x20);
            //如果是字母,则进入sw_schema处理
            if (c >= 'a' && c <= 'z') {
                r->schema_start = p;
                state = sw_schema;
                break;
            }

            switch (ch) {
            //如果是以/开始,则进入sw_after_slash_in_uri
            case '/':
                r->uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            //空格的话继续这个状态。
            case ' ':
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        //sw_schema状态主要是用来解析协议类型。等到协议类型解析完毕则进入sw_schema_slash状态.
        case sw_schema:

            c = (u_char) (ch | 0x20);
            //如果是字母则break,然后继续这个状态的处理。
            if (c >= 'a' && c <= 'z') {
                break;
            }

            //到这里说明schema已经结束。
            switch (ch) {
            //这里必须是:,如果不是冒号则直接返回错误。
            case ':':
                //设置schema_end,而start我们在上面已经设置过了
                r->schema_end = p;
                //设置下一个状态。
                state = sw_schema_slash;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;
        // sw_schema_slash和sw_schema_slash_slash是两个很简单的状态,第一个是得到schema的第一个/,然后进
        // 入sw_schema_slash_slash,而sw_schema_slash_slash则是得到了第二个/.然后进入sw_host。
        case sw_schema_slash:
            switch (ch) {
            case '/':
                //进入slash_slash
                state = sw_schema_slash_slash;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_schema_slash_slash:
            switch (ch) {
            case '/':
                //设置host的开始指针
                r->host_start = p;
                //设置下一个状态为sw_host.
                state = sw_host;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        // 然后是sw_host状态,这个状态用来解析host。
        case sw_host:

            c = (u_char) (ch | 0x20);
            // 两个判断可以写在一起？
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-')
            {
                break;
            }

            switch (ch) {
            case ':':
                //到达这里说明host已经得到,因此设置end指针。
                //冒号说明host有跟端口的,因此进入port状态。
                r->host_end = p;
                state = sw_port;
                break;
            case '/':
                //这个说明要开始解析path了。因此设置uri的start,然后进入slash_in_uri
                r->host_end = p;
                r->uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        // 接下来是sw_port,这个状态用来解析协议端口。
        case sw_port:
            if (ch >= '0' && ch <= '9') {
                break;
            }
            //如果到达这里说明端口解析完毕, 然后就来判断下一步需要的状态。
            switch (ch) {
            //如果紧跟着/,则说明后面是uri,因此进入uri解析,并设置port_end
            case '/':
                r->port_end = p;
                r->uri_start = p;
                state = sw_after_slash_in_uri;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* check "/.", "//", "%", and "\" (Win32) in URI */
        // 接下来是sw_after_slash_in_uri,sw_check_uri 这两个状态都是解析uri之前的状态,
        // 主要用于检测uri, 比如complex uri等
        case sw_after_slash_in_uri:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                state = sw_check_uri;
                break;
            }

            if (ch >= '0' && ch <= '9') {
                state = sw_check_uri;
                break;
            }

            switch (ch) {
            case ' ':
                r->uri_end = p;
                state = sw_http_09;
                break;
            case CR:
                r->uri_end = p;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p;
                r->http_minor = 9;
                goto done;
            case '.':
                r->complex_uri = 1;
                state = sw_uri;
                break;
            case '%':
                r->quoted_uri = 1;
                state = sw_uri;
                break;
            case '/':
                r->complex_uri = 1;
                state = sw_uri;
                break;
#if (NGX_WIN32)
            case '\\':
                r->complex_uri = 1;
                state = sw_uri;
                break;
#endif
            case '?':
                r->args_start = p + 1;
                state = sw_uri;
                break;
            case '+':
                r->plus_in_uri = 1;
                break;
            case '\0':
                r->zero_in_uri = 1;
                break;
            default:
                state = sw_check_uri;
                break;
            }
            break;

        /* check "/", "%" and "\" (Win32) in URI */
        case sw_check_uri:

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if (ch >= '0' && ch <= '9') {
                break;
            }

            switch (ch) {
            case '/':
                r->uri_ext = NULL;
                state = sw_after_slash_in_uri;
                break;
            case '.':
                r->uri_ext = p + 1;
                break;
            case ' ':
                r->uri_end = p;
                state = sw_http_09;
                break;
            case CR:
                r->uri_end = p;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p;
                r->http_minor = 9;
                goto done;
#if (NGX_WIN32)
            case '\\':
                r->complex_uri = 1;
                state = sw_after_slash_in_uri;
                break;
#endif
            case '%':
                r->quoted_uri = 1;
                state = sw_uri;
                break;
            case '?':
                r->args_start = p + 1;
                state = sw_uri;
                break;
            case '+':
                r->plus_in_uri = 1;
                break;
            case '\0':
                r->zero_in_uri = 1;
                break;
            }
            break;

        /* URI */
        // 这个状态就是开始解析uri。这里可以看到对http 0.9是特殊处理的,如果直接是回车或者换行的话,就进入http 0.9的处理。
        case sw_uri:
            switch (ch) {
            //下面三种情况都说明是http 0.9
            case ' ':
                r->uri_end = p;
                state = sw_http_09;
                break;
            case CR:
                r->uri_end = p;
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->uri_end = p;
                r->http_minor = 9;
                goto done;
            case '\0':
                r->zero_in_uri = 1;
                break;
            }
            break;

        // 接下来的sw_http_09,sw_http_H,sw_http_HT,sw_http_HTT,sw_http_HTTP,
        //sw_first_major_digit,sw_major_digit,sw_first_minor_digit,sw_minor_digit,这几个状态主要是用来解析http
        //的版本号的,都比较简单
        /* space+ after URI */
        case sw_http_09:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->http_minor = 9;
                state = sw_almost_done;
                break;
            case LF:
                r->http_minor = 9;
                goto done;
            case 'H':
                r->http_protocol.data = p;
                state = sw_http_H;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_H:
            switch (ch) {
            case 'T':
                state = sw_http_HT;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HT:
            switch (ch) {
            case 'T':
                state = sw_http_HTT;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HTT:
            switch (ch) {
            case 'P':
                state = sw_http_HTTP;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        case sw_http_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
            break;

        /* first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_major = ch - '0';
            state = sw_major_digit;
            break;

        /* major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_major = r->http_major * 10 + ch - '0';
            break;

        /* first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_minor = ch - '0';
            state = sw_minor_digit;
            break;

        /* minor HTTP version or end of request line */
        case sw_minor_digit:
            if (ch == CR) {
                //如果是回车,则进入almost_done,然后等待最后一个换行。
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                //如果是换行则说明request-line解析完毕
                goto done;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            r->http_minor = r->http_minor * 10 + ch - '0';
            break;

        /* end of request line */
        //最后是almost_done状态,也就是等待最后的换行。
        case sw_almost_done:
            r->request_end = p - 1;
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }
        }
    }

    b->pos = p;
    r->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;

    if (r->request_end == NULL) {
        r->request_end = p;
    }

    r->http_version = r->http_major * 1000 + r->http_minor;
    r->state = sw_start;

    if (r->http_version == 9 && r->method != NGX_HTTP_GET) {
        return NGX_HTTP_PARSE_INVALID_09_METHOD;
    }

    return NGX_OK;
}

/**
 *  此函数直解析一个header 供ngx_http_process_request_headers调用
 * @param r
 * @param b
 * @return
 * 而这个函数能够返回三个值,第一个是NGX_OK,这个表示一个header解析完毕,
 * 第二个是NGX_AGAIN,表示header没有解析完毕,也就是说buf只有一部分的数据。这个时候,下次进来的数据会继续没有完成的解析。
 * 第三个是NGX_HTTP_PARSE_HEADER_DONE;,表示整个header已经解析完毕。
 */
ngx_int_t
ngx_http_parse_header_line(ngx_http_request_t *r, ngx_buf_t *b)
{
    u_char      c, ch, *p;
    ngx_uint_t  hash, i;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_ignore_line,
        sw_almost_done,
        sw_header_almost_done
    } state;

    static u_char  lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    state = r->state;
    hash = r->header_hash;
    i = r->lowcase_index;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:
            r->invalid_header = 0;

            //通过第一个字符的值来判断下一个状态。
            switch (ch) {
            //回车的话,说明没有header,因此设置状态为almost_done,然后期待最后的换行
            case CR:
                r->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                //如果换行则直接进入header_done,也就是整个header解析完毕
                r->header_end = p;
                goto header_done;
            default:
                //默认进入sw_name状态,进行name解析
                state = sw_name;
                r->header_name_start = p;
                //这里做了一个表,来进行大小写转换
                c = lowcase[ch];

                if (c) {
                    //得到hash值,然后设置lowcase_header,后面我会解释这两个操作的原因。
                    hash = ngx_hash(0, c);
                    r->lowcase_header[0] = c;
                    i = 1;
                    break;
                }

                r->invalid_header = 1;

                break;

            }
            break;

        /* header name */
        // 然后是sw_name状态,这个状态进行解析name。
        case sw_name:
            //小写。
            c = lowcase[ch];
            //开始计算hash,然后保存header name
            if (c) {
                hash = ngx_hash(hash, c);
                r->lowcase_header[i++] = c;
                i &= ~NGX_HTTP_LC_HEADER_LEN;
                break;
            }

            //如果是冒号,则进入value的处理,由于value有可能前面有空格,因此先处理这个。
            if (ch == ':') {
                // 设置header name的end。
                r->header_name_end = p;
                state = sw_space_before_value;
                break;
            }
            //如果是回车换行则说明当前header解析已经结束,因此进入最终结束处理。
            if (ch == CR) {
                //设置对应的值。
                r->header_name_end = p;
                r->header_start = p;
                r->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                //设置对应的值,然后进入done
                r->header_name_end = p;
                r->header_start = p;
                r->header_end = p;
                goto done;
            }

            /* IIS may send the duplicate "HTTP/1.1 ..." lines */
            if (ch == '/'
                && r->upstream
                && p - r->header_name_start == 4
                && ngx_strncmp(r->header_name_start, "HTTP", 4) == 0)
            {
                state = sw_ignore_line;
                break;
            }

            r->invalid_header = 1;

            break;

        /* space* before header value */
        // sw_space_before_value状态就不分析了,这里它主要是解析value有空格的情况,并且保存value的指针。
        case sw_space_before_value:
            switch (ch) {
            //跳过空格
            case ' ':
                break;
            case CR:
                r->header_start = p;
                r->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                r->header_start = p;
                r->header_end = p;
                goto done;
            default:
                //设置header_start也就是value的开始指针。
                r->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        // 我们主要来看sw_value状态,也就是解析value的状态。
        case sw_value:
            switch (ch) {
                //如果是空格则进入sw_space_after_value处理
            case ' ':
                r->header_end = p;
                state = sw_space_after_value;
                break;
                    //会车换行的话,说明header解析完毕进入done或者almost_done.也就是最终会返回NGX_OK
            case CR:
                r->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                r->header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* ignore header line */
        case sw_ignore_line:
            switch (ch) {
            case LF:
                state = sw_start;
                break;
            default:
                break;
            }
            break;

        /* end of header line */
        //最后来看两个结束状态
                //当前的header解析完毕
        case sw_almost_done:
            switch (ch) {
            case CR:
                break;
            case LF:
                goto done;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
            break;

        /* end of header */
                //整个header解析完毕
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
        }
    }
    // 首先是默认,也就是当遍历完buf后,header仍然没有结束的情况:
    // 此时设置对应的hash值,以及保存当前状态,以及buf的位置
    b->pos = p;
    r->state = state;
    r->header_hash = hash;
    r->lowcase_index = i;

    return NGX_AGAIN;

// 然后是done,也就是当前的header已经解析完毕,此时设置状态为start,以及buf位置为p+1.
done:

    b->pos = p + 1;
    r->state = sw_start;
    r->header_hash = hash;
    r->lowcase_index = i;

    return NGX_OK;

//最后是header全部解析完毕,此时是得到了最后的回车换行,因此不需要hash值。
header_done:

    b->pos = p + 1;
    r->state = sw_start;

    return NGX_HTTP_PARSE_HEADER_DONE;
}


ngx_int_t
ngx_http_parse_complex_uri(ngx_http_request_t *r)
{
    u_char  c, ch, decoded, *p, *u;
    enum {
        sw_usual = 0,
        sw_slash,
        sw_dot,
        sw_dot_dot,
#if (NGX_WIN32)
        sw_dot_dot_dot,
#endif
        sw_quoted,
        sw_quoted_second
    } state, quoted_state;

#if (NGX_SUPPRESS_WARN)
    decoded = '\0';
    quoted_state = sw_usual;
#endif

    state = sw_usual;
    p = r->uri_start;
    u = r->uri.data;
    r->uri_ext = NULL;
    r->args_start = NULL;

    ch = *p++;

    while (p <= r->uri_end) {

        /*
         * we use "ch = *p++" inside the cycle, but this operation is safe,
         * because after the URI there is always at least one charcter:
         * the line feed
         */

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "s:%d in:'%Xd:%c', out:'%c'", state, ch, ch, *u);

        switch (state) {

        case sw_usual:
            switch(ch) {
#if (NGX_WIN32)
            case '\\':
                r->uri_ext = NULL;

                if (p == r->uri_start + r->uri.len) {

                    /*
                     * we omit the last "\" to cause redirect because
                     * the browsers do not treat "\" as "/" in relative URL path
                     */

                    break;
                }

                state = sw_slash;
                *u++ = '/';
                break;
#endif
            case '/':
                r->uri_ext = NULL;
                state = sw_slash;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->args_start = p;
                goto done;
            case '.':
                r->uri_ext = u + 1;
                *u++ = ch;
                break;
            case '+':
                r->plus_in_uri = 1;
            default:
                *u++ = ch;
                break;
            }
            ch = *p++;
            break;

        case sw_slash:
            switch(ch) {
#if (NGX_WIN32)
            case '\\':
#endif
            case '/':
                break;
            case '.':
                state = sw_dot;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->args_start = p;
                goto done;
            case '+':
                r->plus_in_uri = 1;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }
            ch = *p++;
            break;

        case sw_dot:
            switch(ch) {
#if (NGX_WIN32)
            case '\\':
#endif
            case '/':
                state = sw_slash;
                u--;
                break;
            case '.':
                state = sw_dot_dot;
                *u++ = ch;
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->args_start = p;
                goto done;
            case '+':
                r->plus_in_uri = 1;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }
            ch = *p++;
            break;

        case sw_dot_dot:
            switch(ch) {
#if (NGX_WIN32)
            case '\\':
#endif
            case '/':
                state = sw_slash;
                u -= 4;
                if (u < r->uri.data) {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
                while (*(u - 1) != '/') {
                    u--;
                }
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->args_start = p;
                goto done;
#if (NGX_WIN32)
            case '.':
                state = sw_dot_dot_dot;
                *u++ = ch;
                break;
#endif
            case '+':
                r->plus_in_uri = 1;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }
            ch = *p++;
            break;

#if (NGX_WIN32)
        case sw_dot_dot_dot:
            switch(ch) {
            case '\\':
            case '/':
                state = sw_slash;
                u -= 5;
                if (u < r->uri.data) {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
                while (*u != '/') {
                    u--;
                }
                if (u < r->uri.data) {
                    return NGX_HTTP_PARSE_INVALID_REQUEST;
                }
                while (*(u - 1) != '/') {
                    u--;
                }
                break;
            case '%':
                quoted_state = state;
                state = sw_quoted;
                break;
            case '?':
                r->args_start = p;
                goto done;
            case '+':
                r->plus_in_uri = 1;
            default:
                state = sw_usual;
                *u++ = ch;
                break;
            }
            ch = *p++;
            break;
#endif

        case sw_quoted:
            r->quoted_uri = 1;

            if (ch >= '0' && ch <= '9') {
                decoded = (u_char) (ch - '0');
                state = sw_quoted_second;
                ch = *p++;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                decoded = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                ch = *p++;
                break;
            }

            return NGX_HTTP_PARSE_INVALID_REQUEST;

        case sw_quoted_second:
            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((decoded << 4) + ch - '0');

                if (ch == '%') {
                    state = sw_usual;
                    *u++ = ch;
                    ch = *p++;
                    break;
                }

                if (ch == '\0') {
                    r->zero_in_uri = 1;
                }

                state = quoted_state;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((decoded << 4) + c - 'a' + 10);

                if (ch == '?') {
                    *u++ = ch;
                    ch = *p++;

                } else if (ch == '+') {
                    r->plus_in_uri = 1;
                }

                state = quoted_state;
                break;
            }

            return NGX_HTTP_PARSE_INVALID_REQUEST;
        }
    }

done:

    r->uri.len = u - r->uri.data;
    r->uri.data[r->uri.len] = '\0';

    if (r->uri_ext) {
        r->exten.len = u - r->uri_ext;
        r->exten.data = r->uri_ext;
    }

    r->uri_ext = NULL;

    return NGX_OK;
}


ngx_int_t
ngx_http_parse_unsafe_uri(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_str_t *args, ngx_uint_t *flags)
{
    u_char  ch, *p;
    size_t  len;

    len = uri->len;
    p = uri->data;

    if (len == 0 || p[0] == '?') {
        goto unsafe;
    }

    if (p[0] == '.' && len == 3 && p[1] == '.' && (p[2] == '/'
#if (NGX_WIN32)
                                                   || p[2] == '\\'
#endif
        ))
    {
        goto unsafe;
    }

    for ( /* void */ ; len; len--) {

        ch = *p++;

        if (ch == '?') {
            args->len = len - 1;
            args->data = p;
            uri->len -= len;

            return NGX_OK;
        }

        if (ch == '\0') {
            *flags |= NGX_HTTP_ZERO_IN_URI;
            continue;
        }

        if (ch != '/'
#if (NGX_WIN32)
            && ch != '\\'
#endif
            )
        {
            continue;
        }

        if (len > 2) {

            /* detect "/../" */

            if (p[0] == '.' && p[1] == '.' && p[2] == '/') {
                goto unsafe;
            }

#if (NGX_WIN32)

            if (p[2] == '\\') {
                goto unsafe;
            }

            if (len > 3) {

                /* detect "/.../" */

                if (p[0] == '.' && p[1] == '.' && p[2] == '.'
                    && (p[3] == '/' || p[3] == '\\'))
                {
                    goto unsafe;
                }
            }
#endif
        }
    }

    return NGX_OK;

unsafe:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "unsafe URI \"%V\" was detected", uri);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_parse_multi_header_lines(ngx_array_t *headers, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_uint_t         i;
    u_char            *start, *last, *end, ch;
    ngx_table_elt_t  **h;

    h = headers->elts;

    for (i = 0; i < headers->nelts; i++) {

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, headers->pool->log, 0,
                       "parse header: \"%V: %V\"", &h[i]->key, &h[i]->value);

        if (name->len > h[i]->value.len) {
            continue;
        }

        start = h[i]->value.data;
        end = h[i]->value.data + h[i]->value.len;

        while (start < end) {

            if (ngx_strncasecmp(start, name->data, name->len) != 0) {
                goto skip;
            }

            for (start += name->len; start < end && *start == ' '; start++) {
                /* void */
            }

            if (value == NULL) {
                if (start == end || *start == ',') {
                    return i;
                }

                goto skip;
            }

            if (start == end || *start++ != '=') {
                /* the invalid header value */
                goto skip;
            }

            while (start < end && *start == ' ') { start++; }

            for (last = start; last < end && *last != ';'; last++) {
                /* void */
            }

            value->len = last - start;
            value->data = start;

            return i;

        skip:

            while (start < end) {
                ch = *start++;
                if (ch == ';' || ch == ',') {
                    break;
                }
            }

            while (start < end && *start == ' ') { start++; }
        }
    }

    return NGX_DECLINED;
}
