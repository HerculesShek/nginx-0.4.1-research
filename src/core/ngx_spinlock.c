
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>

/**
 * 在ngx_shmtx.h中
 *  #define ngx_shmtx_lock(mtx)   ngx_spinlock((mtx)->lock, ngx_pid, 1024)
 *
 * NGX_HAVE_ATOMIC_OPS 必须支持原子操作 才有这个函数
 *
 * 这里和ngx_shmtx_trylock的处理差不多,都是利用原子指令来实现的,只不过这里如果无法获得锁,则会继续等待。
 *
 * @param lock
 * @param value
 * @param spin      general 1024
 */
void
ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin)
{

#if (NGX_HAVE_ATOMIC_OPS)

    ngx_uint_t  i, n;

    for ( ;; ) {

        //如果lock为0,则说明没有进程持有锁,因此设置lock为value(为当前进程id),然后返回。
        if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
            return;
        }

        //如果cpu个数大于1(也就是多核),则进入spin-wait loop阶段。
        if (ngx_ncpu > 1) {

            for (n = 1; n < spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    // 就是pause指令
                    ngx_cpu_pause();
                }

                //然后重新获取锁,如果获得则直接返回。
                if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
                    return;
                }
            }
        }

        //这个函数调用的是sched_yield,它会强迫当前运行的进程放弃占有处理器。
        ngx_sched_yield();
    }

#else

#if (NGX_THREADS)

#error ngx_spinlock() or ngx_atomic_cmp_set() are not defined !

#endif

#endif

}
