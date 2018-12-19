cmake_minimum_required(VERSION 3.6)
project(nginx)


set(CMAKE_C_FLAGS "-pipe -Wall -Wextra -Wpointer-arith -Wconditional-uninitialized -Wno-unused-parameter -Wno-deprecated-declarations")

#message("\nhi")
#message(${nginx0.4.1_SOURCE_DIR}) # /Users/will/github/nginx
#message(${PROJECT_BINARY_DIR}) # /Users/will/github/nginx/cmake-build-debug
include_directories(src/auto
        src/core
        src/event
        src/event/modules
        src/http
        src/http/modules
        src/http/modules/perl
        src/mysql
        src/os
        objs
        src/os/unix
        src/http/modules/proxy
        src/imap)

set(SOURCE_FILES
        src/imap/ngx_imap_parse.c
        src/imap/ngx_imap.c
        src/imap/ngx_imap_proxy_module.c
        src/imap/ngx_imap_ssl_module.h
        src/imap/ngx_imap_auth_http_module.c
        src/imap/ngx_imap_core_module.c
        src/imap/ngx_imap_handler.c
        src/imap/ngx_imap.h
        src/imap/ngx_imap_ssl_module.c


        src/core/ngx_unix_domain.c
        src/core/ngx_shmtx.h
        src/core/ngx_regex.h
        src/core/ngx_log.c
        src/core/ngx_cpuinfo.c
        src/core/ngx_cycle.h
        src/core/ngx_palloc.c
        src/core/ngx_list.h
        src/core/ngx_slab.h
        src/core/ngx_times.h
        src/core/ngx_radix_tree.c
        src/core/ngx_output_chain.c
        src/core/ngx_parse.h
        src/core/ngx_string.c
        src/core/ngx_crc.h
        src/core/nginx.h
        src/core/ngx_array.c
        src/core/ngx_inet.c
        src/core/ngx_rbtree.c
        src/core/ngx_file.c
        src/core/ngx_connection.h
        src/core/ngx_resolver.c
        src/core/ngx_garbage_collector.c
        src/core/ngx_buf.h
        src/core/ngx_config.h
        src/core/ngx_conf_file.c
        src/core/ngx_hash.h
        src/core/ngx_slab.c
        src/core/ngx_list.c
        src/core/ngx_palloc.h
        src/core/ngx_core.h
        src/core/ngx_log.h
        src/core/ngx_cycle.c
        src/core/ngx_shmtx.c
        src/core/ngx_regex.c
        src/core/ngx_unix_domain.h
        src/core/ngx_string.h
        src/core/ngx_parse.c
        src/core/ngx_radix_tree.h
        src/core/ngx_times.c
        src/core/ngx_file.h
        src/core/ngx_connection.c
        src/core/ngx_inet.h
        src/core/ngx_array.h
        src/core/ngx_rbtree.h
        src/core/nginx.c
        src/core/ngx_conf_file.h
        src/core/ngx_hash.c
        src/core/ngx_spinlock.c
        src/core/ngx_garbage_collector.h
        src/core/ngx_buf.c

        src/auto/ngx_auto_config.h
        src/auto/ngx_auto_headers.h
        src/auto/ngx_modules.c


        src/http/ngx_http_header_filter_module.c
        src/http/ngx_http_core_module.h
        src/http/ngx_http_parse_time.c
        src/http/ngx_http_variables.h
        src/http/ngx_http_special_response.c
        src/http/ngx_http.c
        src/http/ngx_http_write_filter_module.c
        src/http/ngx_http_upstream.h
        src/http/ngx_http_request_body.c
        src/http/ngx_http_postpone_filter_module.c
        src/http/ngx_http_script.c
        src/http/ngx_http_cache.h
        src/http/ngx_http_busy_lock.h
        src/http/ngx_http_file_cache.c
        src/http/ngx_http_request.c
        src/http/ngx_http_variables.c
        src/http/ngx_http_core_module.c
        src/http/ngx_http_upstream.c
        src/http/ngx_http.h
        src/http/ngx_http_config.h
        src/http/ngx_http_script.h


        src/http/modules/ngx_http_dav_module.c
        src/http/modules/ngx_http_log_module.c
        src/http/modules/ngx_http_gzip_filter_module.c
        src/http/modules/ngx_http_range_filter_module.c
        src/http/modules/ngx_http_ssl_module.c
        src/http/modules/ngx_http_geo_module.c
        src/http/modules/ngx_http_charset_filter_module.c
        src/http/modules/ngx_http_realip_module.c
        src/http/modules/ngx_http_autoindex_module.c
        src/http/modules/ngx_http_memcached_module.c
        src/http/modules/ngx_http_ssi_filter_module.c


        src/http/modules/perl/ngx_http_perl_module.c
        src/http/modules/perl/nginx.pm
        src/http/modules/perl/typemap
        src/http/modules/perl/Makefile.PL
        src/http/modules/perl/ngx_http_perl_module.h
        src/http/modules/perl/nginx.xs
        src/http/modules/ngx_http_not_modified_filter_module.c
        src/http/modules/ngx_http_index_module.c
        src/http/modules/ngx_http_log_module.h
        src/http/modules/ngx_http_auth_basic_module.c
        src/http/modules/ngx_http_rewrite_module.c
        src/http/modules/ngx_http_ssl_module.h
        src/http/modules/ngx_http_referer_module.c
        src/http/modules/ngx_http_empty_gif_module.c
        src/http/modules/ngx_http_access_module.c
        src/http/modules/ngx_http_addition_filter_module.c
        src/http/modules/ngx_http_status_module.c
        src/http/modules/ngx_http_fastcgi_module.c
        src/http/modules/ngx_http_ssi_filter_module.h
        src/http/modules/ngx_http_userid_filter_module.c
        src/http/modules/ngx_http_headers_filter_module.c
        src/http/modules/ngx_http_map_module.c
        src/http/modules/ngx_http_proxy_module.c
        src/http/modules/ngx_http_static_module.c
        src/http/modules/ngx_http_chunked_filter_module.c
        src/http/modules/ngx_http_stub_status_module.c
        src/http/ngx_http_parse.c
        src/http/ngx_http_copy_filter_module.c
        src/http/ngx_http_busy_lock.c
        src/http/ngx_http_cache.c
        src/http/ngx_http_request.h


        src/mysql/ngx_http_mysql_test.c
        src/mysql/ngx_mysql.c
        src/mysql/config
        src/mysql/ngx_mysql.h


        src/os/unix/ngx_freebsd_sendfile_chain.c
        src/os/unix/ngx_time.c
        src/os/unix/ngx_recv.c
        src/os/unix/ngx_solaris_sendfilev_chain.c
        src/os/unix/ngx_writev_chain.c
        src/os/unix/ngx_alloc.c
        src/os/unix/ngx_linux.h
        src/os/unix/ngx_files.c
        src/os/unix/ngx_aio.h
        src/os/unix/ngx_socket.c
        src/os/unix/rfork_thread.S
        src/os/unix/ngx_readv_chain.c
        src/os/unix/ngx_sunpro_atomic_sparc64.h
        src/os/unix/ngx_gcc_atomic_sparc64.h
        src/os/unix/ngx_user.h
        src/os/unix/ngx_errno.c
        src/os/unix/ngx_process_cycle.h
        src/os/unix/ngx_process.h
        src/os/unix/ngx_shmem.c
        src/os/unix/ngx_sunpro_amd64.il
        src/os/unix/ngx_freebsd.h
        src/os/unix/ngx_gcc_atomic_ppc.h
        src/os/unix/ngx_sunpro_x86.il
        src/os/unix/ngx_os.h
        src/os/unix/ngx_sunpro_sparc64.il
        src/os/unix/ngx_linux_config.h
        src/os/unix/ngx_types.h
        src/os/unix/ngx_pthread_thread.c
        src/os/unix/ngx_linux_init.c
        src/os/unix/ngx_aio_read.c
        src/os/unix/ngx_setproctitle.c
        src/os/unix/ngx_channel.c
        src/os/unix/ngx_solaris_config.h
        src/os/unix/ngx_freebsd_rfork_thread.c
        src/os/unix/ngx_gcc_atomic_x86.h
        src/os/unix/ngx_alloc.h
        src/os/unix/ngx_aio_read_chain.c
        src/os/unix/ngx_posix_init.c
        src/os/unix/ngx_time.h
        src/os/unix/ngx_posix_config.h
        src/os/unix/ngx_solaris_init.c
        src/os/unix/ngx_errno.h
        src/os/unix/ngx_atomic.h
        src/os/unix/ngx_aio_write.c
        src/os/unix/ngx_user.c
        src/os/unix/ngx_send.c
        src/os/unix/ngx_socket.h
        src/os/unix/ngx_linux_sendfile_chain.c
        src/os/unix/ngx_solaris.h
        src/os/unix/ngx_files.h
        src/os/unix/ngx_thread.h
        src/os/unix/ngx_aio_write_chain.c
        src/os/unix/ngx_freebsd_config.h
        src/os/unix/ngx_shmem.h
        src/os/unix/ngx_process.c
        src/os/unix/ngx_process_cycle.c
        src/os/unix/ngx_freebsd_rfork_thread.h
        src/os/unix/ngx_channel.h
        src/os/unix/ngx_setproctitle.h
        src/os/unix/ngx_daemon.c
        src/os/unix/ngx_gcc_atomic_amd64.h
        src/os/unix/ngx_freebsd_init.c


        src/event/ngx_event_connectex.c
        src/event/ngx_event_accept.c
        src/event/ngx_event_posted.h
        src/event/ngx_event_acceptex.c
        src/event/ngx_event_connect.c
        src/event/ngx_event.h
        src/event/ngx_event_timer.h
        src/event/ngx_event_openssl.c
        src/event/ngx_event_pipe.c
        src/event/ngx_event_busy_lock.c
        src/event/ngx_event_mutex.c
        src/event/ngx_event_posted.c
        src/event/ngx_event.c
        src/event/ngx_event_openssl.h
        src/event/ngx_event_timer.c
        src/event/ngx_event_connect.h


        src/event/modules/ngx_epoll_module.c
        src/event/modules/ngx_iocp_module.h
        src/event/modules/ngx_kqueue_module.h
        src/event/modules/ngx_aio_module.c
        src/event/modules/ngx_kqueue_module.c
        src/event/modules/ngx_rtsig_module.c
        src/event/modules/ngx_iocp_module.c
        src/event/modules/ngx_select_module.c
        src/event/modules/ngx_aio_module.h
        src/event/modules/ngx_devpoll_module.c
        src/event/modules/ngx_poll_module.c
        src/event/ngx_event_busy_lock.h
        src/event/ngx_event_pipe.h)

#
add_executable(nginx ${SOURCE_FILES})
target_link_libraries(nginx -lpcre -lz)

add_executable(flist tools/flist.c)