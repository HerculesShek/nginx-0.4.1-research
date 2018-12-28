
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>


static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n,
    ngx_int_t type);
static void ngx_start_garbage_collector(ngx_cycle_t *cycle, ngx_int_t type);
static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo);
static ngx_uint_t ngx_reap_childs(ngx_cycle_t *cycle);
static void ngx_master_process_exit(ngx_cycle_t *cycle);
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_worker_process_init(ngx_cycle_t *cycle, ngx_uint_t priority);
static void ngx_worker_process_exit(ngx_cycle_t *cycle);
static void ngx_channel_handler(ngx_event_t *ev);
#if (NGX_THREADS)
static void ngx_wakeup_worker_threads(ngx_cycle_t *cycle);
static ngx_thread_value_t ngx_worker_thread_cycle(void *data);
#endif
#if 0
static void ngx_garbage_collector_cycle(ngx_cycle_t *cycle, void *data);
#endif


ngx_uint_t    ngx_process; // 标记当前进程类型  NGX_PROCESS_MASTER / NGX_PROCESS_SINGLE / NGX_PROCESS_WORKER
ngx_pid_t     ngx_pid;     // 标记当前进程pid
ngx_uint_t    ngx_threaded;

sig_atomic_t  ngx_reap;
sig_atomic_t  ngx_sigio;
sig_atomic_t  ngx_terminate;
sig_atomic_t  ngx_quit;
sig_atomic_t  ngx_debug_quit;
ngx_uint_t    ngx_exiting;
sig_atomic_t  ngx_reconfigure;
sig_atomic_t  ngx_reopen;

sig_atomic_t  ngx_change_binary;
ngx_pid_t     ngx_new_binary;
ngx_uint_t    ngx_inherited;
ngx_uint_t    ngx_daemonized;

sig_atomic_t  ngx_noaccept;
ngx_uint_t    ngx_noaccepting;
ngx_uint_t    ngx_restart;


#if (NGX_THREADS)
volatile ngx_thread_t  ngx_threads[NGX_MAX_THREADS];
ngx_int_t              ngx_threads_n;
#endif


u_long         cpu_affinity;
static u_char  master_process[] = "master process";


/**
 * nginx主进程轮转
 *
 * @param cycle
 */
void
ngx_master_process_cycle(ngx_cycle_t *cycle)
{
    char              *title;
    u_char            *p;
    size_t             size;
    ngx_int_t          i;
    ngx_uint_t         n;
    sigset_t           set;
    struct itimerval   itv;
    ngx_uint_t         live;
    ngx_msec_t         delay;
    ngx_listening_t   *ls;
    ngx_core_conf_t   *ccf;

    // 初始化信号集 并设置接受相关的信号
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL)); // SIGHUP
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL)); // SIGUSR1
    sigaddset(&set, ngx_signal_value(NGX_NOACCEPT_SIGNAL)); //SIGWINCH
    sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL)); //SIGTERM
    sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL)); //SIGQUIT
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL)); // SIGUSR2

    // 把以上信号全部加入主进程信号屏蔽字中！主进程从此不接受上面的信号
    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }
    // 置空set信号集 用于sigsuspend
    sigemptyset(&set);


    size = sizeof(master_process);

    for (i = 0; i < ngx_argc; i++) {
        size += ngx_strlen(ngx_argv[i]) + 1;
    }

    title = ngx_palloc(cycle->pool, size);

    p = ngx_cpymem(title, master_process, sizeof(master_process) - 1);
    for (i = 0; i < ngx_argc; i++) {
        *p++ = ' ';
        p = ngx_cpystrn(p, (u_char *) ngx_argv[i], size);
    }

    ngx_setproctitle(title);


    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    ngx_start_worker_processes(cycle, ccf->worker_processes,
                               NGX_PROCESS_RESPAWN);
    ngx_start_garbage_collector(cycle, NGX_PROCESS_RESPAWN);

    ngx_new_binary = 0;
    delay = 0;
    live = 1;

    for ( ;; ) { /* 主进程轮转 master cycle */
        // delay用来等待子进程退出的时间,由于我们接受到SIGINT信号后,
        // 我们需要先发送信号给子进程,而子进程的退出需要一定的时间,超时时如果子进程已退出,
        // 我们父进程就直接退出,否则发送sigkill信号给子进程(强制退出),然后再退出。
        if (delay) {
            delay *= 2;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "temination cycle: %d", delay);

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;
            // 设置定时器
            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "setitimer() failed");
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");

        // 延时,等待定时器
        /**
         * sigsuspend会让程序挂起 一直等待函数传入的信号集`&set`之外的信号进来 进程才会被重新唤醒
         */
        sigsuspend(&set);

        ngx_time_update(0, 0);

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "wake up");

        // ngx_reap为1,说明有子进程已经退出
        if (ngx_reap) {
            ngx_reap = 0;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "reap childs");

            // 这个里面处理(收割)退出的子进程(有的worker异常退出,这时我们就需要重启这个worker
            live = ngx_reap_childs(cycle);
        }

        // 如果没有存活的子进程前提下 并且收到ngx_terminate或者ngx_quit信号 则master直接退出。
        if (!live && (ngx_terminate || ngx_quit)) {
            ngx_master_process_exit(cycle);
        }

        // 收到了sigint信号 并且有存活的子进程
        if (ngx_terminate) {
            // 设置延时
            if (delay == 0) {
                delay = 50;
            }

            if (delay > 1000) {
                // 如果超时,则强制杀死worker
                ngx_signal_worker_processes(cycle, SIGKILL);
            } else {
                // 负责发送sigint给worker,让它退出
                ngx_signal_worker_processes(cycle,
                                       ngx_signal_value(NGX_TERMINATE_SIGNAL));
            }

            continue;
        }

        // 收到quit信号 并且有存活的子进程
        if (ngx_quit) {
            // 发送给worker quit信号
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));

            ls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {
                if (ngx_close_socket(ls[n].fd) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                                  ngx_close_socket_n " %V failed",
                                  &ls[n].addr_text);
                }
            }
            cycle->listening.nelts = 0;

            continue;
        }

        // 收到需要reconfig的信号
        if (ngx_reconfigure) {
            ngx_reconfigure = 0;

            // 判断是否热代码替换后的新的代码还在运行中(也就是还没退出当前的master)。如果还在运行中,则不需要重新初始化config
            if (ngx_new_binary) {
                ngx_start_worker_processes(cycle, ccf->worker_processes,
                                           NGX_PROCESS_RESPAWN);
                ngx_start_garbage_collector(cycle, NGX_PROCESS_RESPAWN);
                ngx_noaccepting = 0;

                continue;
            }

            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            // 重新初始化config,并重新启动新的worker
            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;
            ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                   ngx_core_module);
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_JUST_RESPAWN);
            ngx_start_garbage_collector(cycle, NGX_PROCESS_JUST_RESPAWN);
            live = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }

        /// 这个标志没弄懂有什么意义。代码里面是当热代码替换后,如果ngx_noacceptig被设置了,则设置这个标志位(难道意思是热代码替换前要先停止当前的accept连接?)
        if (ngx_restart) {
            ngx_restart = 0;
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_RESPAWN);
            ngx_start_garbage_collector(cycle, NGX_PROCESS_RESPAWN);
            live = 1;
        }

        /// 重新打开log USR1信号
        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, ccf->user);
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_REOPEN_SIGNAL));
        }

        ///热代码替换 USR2信号
        if (ngx_change_binary) {
            ngx_change_binary = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "changing binary");
            ///进行热代码替换,这里是调用execve来执行新的代码。
            ngx_new_binary = ngx_exec_new_binary(cycle, ngx_argv);
        }

        ///接受到停止accept连接,其实也就是worker退出(有区别的是,这里master不需要退出). WINCH信号
        if (ngx_noaccept) {
            ngx_noaccept = 0;
            ngx_noaccepting = 1;
            ///给worker发送信号
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }
    } /// end master cycle
}


void
ngx_single_process_cycle(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    ngx_init_temp_number();

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events_and_timers(cycle);

        if (ngx_terminate || ngx_quit) {

            for (i = 0; ngx_modules[i]; i++) {
                if (ngx_modules[i]->exit_process) {
                    ngx_modules[i]->exit_process(cycle);
                }
            }

            ngx_master_process_exit(cycle);
        }

        if (ngx_reconfigure) {
            ngx_reconfigure = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, (ngx_uid_t) -1);
        }
    }
}


/**
 * @param cycle
 * @param n
 * @param type
 */
static void
ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n, ngx_int_t type)
{
    ngx_int_t      i, s;
    ngx_channel_t  ch;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start worker processes");

    // 传递给其他子进程的命令 打开通道命令
    ch.command = NGX_CMD_OPEN_CHANNEL;

    // 这里n,就是从配置文件中读取的,需要fork几个子进程。
    for (i = 0; i < n; i++) {

        cpu_affinity = ngx_get_cpu_affinity(i);
        // fork子进程 worker process
        ngx_spawn_process(cycle, ngx_worker_process_cycle, NULL,
                          "worker process", type);

        // 初始化channel,ngx_process_slot在上面的spawn函数中已经赋值完毕,就是当前子进程的位置。
        ch.pid = ngx_processes[ngx_process_slot].pid;
        ch.slot = ngx_process_slot;
        ch.fd = ngx_processes[ngx_process_slot].channel[0];

        // fork的子进程如何来让前面已经fork的子进程得到自己的进程相关信息呢?
        // 在nginx中是每次新的子进程fork完毕后，然后父进程此时将这个子进程id，以及流管道的句柄channel[0]
        // 通过遍历和ngx_write_channel方法 来传递给之前的子进程。这样子进程之间也可以通信了

        ///遍历整个进程表
        for (s = 0; s < ngx_last_process; s++) {
            // 遇到非存活的进程就跳过
            if (s == ngx_process_slot
                || ngx_processes[s].pid == -1
                || ngx_processes[s].channel[0] == -1)
            {
                continue;
            }

            ngx_log_debug6(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                          "pass channel s:%d pid:%P fd:%d to s:%i pid:%P fd:%d",
                          ch.slot, ch.pid, ch.fd,
                          s, ngx_processes[s].pid,
                          ngx_processes[s].channel[0]);

            /* TODO: NGX_AGAIN */
            // 然后传递这个channel给其他子进程(主要是传递句柄)。
            ngx_write_channel(ngx_processes[s].channel[0],
                              &ch, sizeof(ngx_channel_t), cycle->log);
        }
    }
}


static void
ngx_start_garbage_collector(ngx_cycle_t *cycle, ngx_int_t type)
{
#if 0
    ngx_int_t      i;
    ngx_channel_t  ch;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start garbage collector");

    ch.command = NGX_CMD_OPEN_CHANNEL;

    ngx_spawn_process(cycle, ngx_garbage_collector_cycle, NULL,
                      "garbage collector", type);

    ch.pid = ngx_processes[ngx_process_slot].pid;
    ch.slot = ngx_process_slot;
    ch.fd = ngx_processes[ngx_process_slot].channel[0];

    for (i = 0; i < ngx_last_process; i++) {

        if (i == ngx_process_slot
            || ngx_processes[i].pid == -1
            || ngx_processes[i].channel[0] == -1)
        {
            continue;
        }

        ngx_log_debug6(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                      "pass channel s:%d pid:%P fd:%d to s:%i pid:%P fd:%d",
                      ch.slot, ch.pid, ch.fd,
                      i, ngx_processes[i].pid,
                      ngx_processes[i].channel[0]);

        /* TODO: NGX_AGAIN */

        ngx_write_channel(ngx_processes[i].channel[0],
                          &ch, sizeof(ngx_channel_t), cycle->log);
    }
#endif
}


static void
ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo)
{
    ngx_int_t      i;
    ngx_err_t      err;
    ngx_channel_t  ch;

    switch (signo) {

    case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
        ch.command = NGX_CMD_QUIT;
        break;

    case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        ch.command = NGX_CMD_TERMINATE;
        break;

    case ngx_signal_value(NGX_REOPEN_SIGNAL):
        ch.command = NGX_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

    ch.fd = -1;


    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %d %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_respawn);

        if (ngx_processes[i].detached || ngx_processes[i].pid == -1) {
            continue;
        }

        if (ngx_processes[i].just_respawn) {
            ngx_processes[i].just_respawn = 0;
            continue;
        }

        if (ngx_processes[i].exiting
            && signo == ngx_signal_value(NGX_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        if (ch.command) {
            if (ngx_write_channel(ngx_processes[i].channel[0],
                           &ch, sizeof(ngx_channel_t), cycle->log) == NGX_OK)
            {
                if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
                    ngx_processes[i].exiting = 1;
                }

                continue;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (%P, %d)" , ngx_processes[i].pid, signo);

        if (kill(ngx_processes[i].pid, signo) == -1) {
            err = ngx_errno;
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "kill(%P, %d) failed",
                          ngx_processes[i].pid, signo);

            if (err == NGX_ESRCH) {
                ngx_processes[i].exited = 1;
                ngx_processes[i].exiting = 0;
                ngx_reap = 1;
            }

            continue;
        }

        if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
            ngx_processes[i].exiting = 1;
        }
    }
}


static ngx_uint_t
ngx_reap_childs(ngx_cycle_t *cycle)
{
    ngx_int_t         i, n;
    ngx_uint_t        live;
    ngx_channel_t     ch;
    ngx_core_conf_t  *ccf;

    ch.command = NGX_CMD_CLOSE_CHANNEL;
    ch.fd = -1;

    live = 0;
    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %d %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_respawn);

        if (ngx_processes[i].pid == -1) {
            continue;
        }

        if (ngx_processes[i].exited) {

            if (!ngx_processes[i].detached) {
                ngx_close_channel(ngx_processes[i].channel, cycle->log);

                ngx_processes[i].channel[0] = -1;
                ngx_processes[i].channel[1] = -1;

                ch.pid = ngx_processes[i].pid;
                ch.slot = i;

                for (n = 0; n < ngx_last_process; n++) {
                    if (ngx_processes[n].exited
                        || ngx_processes[n].pid == -1
                        || ngx_processes[n].channel[0] == -1)
                    {
                        continue;
                    }

                    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                                   "pass close channel s:%i pid:%P to:%P",
                                   ch.slot, ch.pid, ngx_processes[n].pid);

                    /* TODO: NGX_AGAIN */

                    ngx_write_channel(ngx_processes[n].channel[0],
                                      &ch, sizeof(ngx_channel_t), cycle->log);
                }
            }

            if (ngx_processes[i].respawn
                && !ngx_processes[i].exiting
                && !ngx_terminate
                && !ngx_quit)
            {
                if (ngx_spawn_process(cycle, ngx_processes[i].proc,
                                      ngx_processes[i].data,
                                      ngx_processes[i].name, i)
                    == NGX_INVALID_PID)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                                  "can not respawn %s", ngx_processes[i].name);
                    continue;
                }


                ch.command = NGX_CMD_OPEN_CHANNEL;
                ch.pid = ngx_processes[ngx_process_slot].pid;
                ch.slot = ngx_process_slot;
                ch.fd = ngx_processes[ngx_process_slot].channel[0];

                for (n = 0; n < ngx_last_process; n++) {

                    if (n == ngx_process_slot
                        || ngx_processes[n].pid == -1
                        || ngx_processes[n].channel[0] == -1)
                    {
                        continue;
                    }

                    ngx_log_debug6(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                          "pass channel s:%d pid:%P fd:%d to s:%i pid:%P fd:%d",
                          ch.slot, ch.pid, ch.fd,
                          n, ngx_processes[n].pid,
                          ngx_processes[n].channel[0]);

                    /* TODO: NGX_AGAIN */

                    ngx_write_channel(ngx_processes[n].channel[0],
                                      &ch, sizeof(ngx_channel_t), cycle->log);
                }

                live = 1;

                continue;
            }

            if (ngx_processes[i].pid == ngx_new_binary) {

                ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                       ngx_core_module);

                if (ngx_rename_file((char *) ccf->oldpid.data,
                                    (char *) ccf->pid.data)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                                  ngx_rename_file_n " %s back to %s failed "
                                  "after the new binary process \"%s\" exited",
                                  ccf->oldpid.data, ccf->pid.data, ngx_argv[0]);
                }

                ngx_new_binary = 0;
                if (ngx_noaccepting) {
                    ngx_restart = 1;
                    ngx_noaccepting = 0;
                }
            }

            if (i == ngx_last_process - 1) {
                ngx_last_process--;

            } else {
                ngx_processes[i].pid = -1;
            }

        } else if (ngx_processes[i].exiting || !ngx_processes[i].detached) {
            live = 1;
        }
    }

    return live;
}


static void
ngx_master_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    ngx_delete_pidfile(cycle);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exit");

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->exit_master) {
            ngx_modules[i]->exit_master(cycle);
        }
    }

    /*
     * we do not destroy cycle->pool here because a signal handler
     * that uses cycle->log can be called at this point
     */

#if 0
    ngx_destroy_pool(cycle->pool);
#endif

    exit(0);
}


static void
ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data)
{
#if (NGX_THREADS)
    ngx_int_t          n;
    ngx_err_t          err;
    ngx_core_conf_t   *ccf;
#endif

    ngx_worker_process_init(cycle, 1);

    ngx_setproctitle("worker process");

#if (NGX_THREADS)

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ngx_threads_n) {
        if (ngx_init_threads(ngx_threads_n,
                                   ccf->thread_stack_size, cycle) == NGX_ERROR)
        {
            /* fatal */
            exit(2);
        }

        err = ngx_thread_key_create(&ngx_core_tls_key);
        if (err != 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          ngx_thread_key_create_n " failed");
            /* fatal */
            exit(2);
        }

        for (n = 0; n < ngx_threads_n; n++) {

            ngx_threads[n].cv = ngx_cond_init(cycle->log);

            if (ngx_threads[n].cv == NULL) {
                /* fatal */
                exit(2);
            }

            if (ngx_create_thread((ngx_tid_t *) &ngx_threads[n].tid,
                                  ngx_worker_thread_cycle,
                                  (void *) &ngx_threads[n], cycle->log) != 0)
            {
                /* fatal */
                exit(2);
            }
        }
    }

#endif

    for ( ;; ) {
        ///ngx_exiting是当收到master的quit命令后，设置为1,然后等待其他资源退出。
        if (ngx_exiting
            && ngx_event_timer_rbtree.root == ngx_event_timer_rbtree.sentinel) /*定时器超时则退出worker*/
        {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");

            ngx_worker_process_exit(cycle);
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events_and_timers(cycle);

        ///收到shutdown命令则worker直接退出
        if (ngx_terminate) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");

            ngx_worker_process_exit(cycle);
        }

        ///收到quit命令
        if (ngx_quit) {
            ngx_quit = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "gracefully shutting down");
            ngx_setproctitle("worker process is shutting down");

            if (!ngx_exiting) {
                ///关闭socket，然后设置退出标志。
                ngx_close_listening_sockets(cycle);
                ngx_exiting = 1;
            }
        }

        ///收到master重新打开log的命令。
        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }
    }
}


static void
ngx_worker_process_init(ngx_cycle_t *cycle, ngx_uint_t priority)
{
    sigset_t           set;
    ngx_int_t          n;
    ngx_uint_t         i;
    struct rlimit      rlmt;
    ngx_core_conf_t   *ccf;
    ngx_listening_t   *ls;

    ngx_process = NGX_PROCESS_WORKER;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (geteuid() == 0) {
        if (priority && ccf->priority != 0) {
            if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "setpriority(%d) failed", ccf->priority);
            }
        }

        if (ccf->rlimit_nofile != NGX_CONF_UNSET) {
            rlmt.rlim_cur = (rlim_t) ccf->rlimit_nofile;
            rlmt.rlim_max = (rlim_t) ccf->rlimit_nofile;

            if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "setrlimit(RLIMIT_NOFILE, %i) failed",
                              ccf->rlimit_nofile);
            }
        }

        if (ccf->rlimit_core != NGX_CONF_UNSET) {
            rlmt.rlim_cur = (rlim_t) ccf->rlimit_core;
            rlmt.rlim_max = (rlim_t) ccf->rlimit_core;

            if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "setrlimit(RLIMIT_CORE, %i) failed",
                              ccf->rlimit_core);
            }
        }

#ifdef RLIMIT_SIGPENDING
        if (ccf->rlimit_sigpending != NGX_CONF_UNSET) {
            rlmt.rlim_cur = (rlim_t) ccf->rlimit_sigpending;
            rlmt.rlim_max = (rlim_t) ccf->rlimit_sigpending;

            if (setrlimit(RLIMIT_SIGPENDING, &rlmt) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "setrlimit(RLIMIT_SIGPENDING, %i) failed",
                              ccf->rlimit_sigpending);
            }
        }
#endif

        if (setgid(ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }

        if (initgroups(ccf->username, ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "initgroups(%s, %d) failed",
                          ccf->username, ccf->group);
        }

        if (setuid(ccf->user) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }
    }

#if (NGX_HAVE_SCHED_SETAFFINITY)

    if (cpu_affinity) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "sched_setaffinity(0x%08Xl)", cpu_affinity);

        if (sched_setaffinity(0, 32, (cpu_set_t *) &cpu_affinity) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "sched_setaffinity(0x%08Xl) failed", cpu_affinity);
        }
    }

#endif

#if (NGX_HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "prctl(PR_SET_DUMPABLE) failed");
    }

#endif

    if (ccf->working_directory.len) {
        if (chdir((char *) ccf->working_directory.data) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "chdir(\"%s\") failed", ccf->working_directory.data);
            /* fatal */
            exit(2);
        }
    }

    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    ngx_init_temp_number();

    /*
     * disable deleting previous events for the listening sockets because
     * in the worker processes there are no events at all at this point
     */
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        ls[i].previous = NULL;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for (n = 0; n < ngx_last_process; n++) {

        if (ngx_processes[n].pid == -1) {
            continue;
        }

        if (n == ngx_process_slot) {
            continue;
        }

        if (ngx_processes[n].channel[1] == -1) {
            continue;
        }

        if (close(ngx_processes[n].channel[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "close() channel failed");
        }
    }

    // 子进程中关闭channel[0] 使用channel[1]
    if (close(ngx_processes[ngx_process_slot].channel[0]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() channel failed");
    }

#if 0
    ngx_last_process = 0;
#endif

    if (ngx_add_channel_event(cycle, ngx_channel, NGX_READ_EVENT,
                              ngx_channel_handler) == NGX_ERROR)
    {
        /* fatal */
        exit(2);
    }
}


static void
ngx_worker_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_connection_t  *c;

#if (NGX_THREADS)
    ngx_terminate = 1;

    ngx_wakeup_worker_threads(cycle);
#endif

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->exit_process) {
            ngx_modules[i]->exit_process(cycle);
        }
    }

    if (ngx_quit) {
        c = cycle->connections;
        for (i = 0; i < cycle->connection_n; i++) {
            if (c[i].fd != -1
                && c[i].read
                && !c[i].read->accept
                && !c[i].read->channel)
            {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                              "open socket #%d left in %ui connection, "
                              "aborting",
                              c[i].fd, i);
                ngx_debug_point();
            }
        }

        if (ngx_debug_quit) {
            ngx_debug_point();
        }
    }

    /*
     * we do not destroy cycle->pool here because a signal handler
     * that uses cycle->log can be called at this point
     */

#if 0
    ngx_destroy_pool(cycle->pool);
#endif

    exit(0);
}


/**
 * 在子进程中是如何处理管道中的可读事件呢？
 * 子进程的管道可读事件捕捉函数是ngx_channel_handler
 * @param ev
 */
static void
ngx_channel_handler(ngx_event_t *ev)
{
    ngx_int_t          n;
    ngx_socket_t       fd;
    ngx_channel_t      ch;
    ngx_connection_t  *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel handler");

    n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t), ev->log);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);

    if (n == NGX_ERROR) {

        ngx_free_connection(c);

        fd = c->fd;
        c->fd = (ngx_socket_t) -1;

        if (close(fd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                          "close() channel failed");
        }

        return;
    }

    if (n == NGX_AGAIN) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "channel command: %d", ch.command);
    // 这里ch为读取的channel
    // 读取message,然后解析,并根据不同的命令做不同的处理
    // 就是修改几个当前进程的全局变量而已 在子进程cycle中再读取相关参数
    switch (ch.command) {

    case NGX_CMD_QUIT:
        ngx_quit = 1;
        break;

    case NGX_CMD_TERMINATE:
        ngx_terminate = 1;
        break;

    case NGX_CMD_REOPEN:
        ngx_reopen = 1;
        break;

    case NGX_CMD_OPEN_CHANNEL:
        // 操作很简单,就是对本进程的ngx_processes全局进程表进行赋值
        // 因为后fork的进程信息是拿不到的
        // 注：每个进程的ngx_processes全局进程表在fork时 是不一样的
        ngx_log_debug3(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "get channel s:%i pid:%P fd:%d", ch.slot, ch.pid, ch.fd);

        ngx_processes[ch.slot].pid = ch.pid;
        ngx_processes[ch.slot].channel[0] = ch.fd;
        break;

    case NGX_CMD_CLOSE_CHANNEL:

        ngx_log_debug4(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "close channel s:%i pid:%P our:%P fd:%d",
                       ch.slot, ch.pid, ngx_processes[ch.slot].pid,
                       ngx_processes[ch.slot].channel[0]);

        if (close(ngx_processes[ch.slot].channel[0]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                          "close() channel failed");
        }

        ngx_processes[ch.slot].channel[0] = -1;
        break;
    }
}


#if (NGX_THREADS)

static void
ngx_wakeup_worker_threads(ngx_cycle_t *cycle)
{
    ngx_int_t   i;
    ngx_uint_t  live;

    for ( ;; ) {

        live = 0;

        for (i = 0; i < ngx_threads_n; i++) {
            if (ngx_threads[i].state < NGX_THREAD_EXIT) {
                if (ngx_cond_signal(ngx_threads[i].cv) == NGX_ERROR) {
                    ngx_threads[i].state = NGX_THREAD_DONE;

                } else {
                    live = 1;
                }
            }

            if (ngx_threads[i].state == NGX_THREAD_EXIT) {
                ngx_thread_join(ngx_threads[i].tid, NULL);
                ngx_threads[i].state = NGX_THREAD_DONE;
            }
        }

        if (live == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                           "all worker threads are joined");

            /* STUB */
            ngx_done_events(cycle);
            ngx_mutex_destroy(ngx_event_timer_mutex);
            ngx_mutex_destroy(ngx_posted_events_mutex);

            return;
        }

        ngx_sched_yield();
    }
}


static ngx_thread_value_t
ngx_worker_thread_cycle(void *data)
{
    ngx_thread_t  *thr = data;

    sigset_t          set;
    ngx_err_t         err;
    ngx_core_tls_t   *tls;
    ngx_cycle_t      *cycle;

    cycle = (ngx_cycle_t *) ngx_cycle;

    sigemptyset(&set);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));

    err = ngx_thread_sigmask(SIG_BLOCK, &set, NULL);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      ngx_thread_sigmask_n " failed");
        return (ngx_thread_value_t) 1;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "thread " NGX_TID_T_FMT " started", ngx_thread_self());

    ngx_setthrtitle("worker thread");

    tls = ngx_calloc(sizeof(ngx_core_tls_t), cycle->log);
    if (tls == NULL) {
        return (ngx_thread_value_t) 1;
    }

    err = ngx_thread_set_tls(ngx_core_tls_key, tls);
    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      ngx_thread_set_tls_n " failed");
        return (ngx_thread_value_t) 1;
    }

    ngx_mutex_lock(ngx_posted_events_mutex);

    for ( ;; ) {
        thr->state = NGX_THREAD_FREE;

        if (ngx_cond_wait(thr->cv, ngx_posted_events_mutex) == NGX_ERROR) {
            return (ngx_thread_value_t) 1;
        }

        if (ngx_terminate) {
            thr->state = NGX_THREAD_EXIT;

            ngx_mutex_unlock(ngx_posted_events_mutex);

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                           "thread " NGX_TID_T_FMT " is done",
                           ngx_thread_self());

            return (ngx_thread_value_t) 0;
        }

        thr->state = NGX_THREAD_BUSY;

        if (ngx_event_thread_process_posted(cycle) == NGX_ERROR) {
            return (ngx_thread_value_t) 1;
        }

        if (ngx_event_thread_process_posted(cycle) == NGX_ERROR) {
            return (ngx_thread_value_t) 1;
        }

        if (ngx_process_changes) {
            if (ngx_process_changes(cycle, 1) == NGX_ERROR) {
                return (ngx_thread_value_t) 1;
            }
        }
    }
}

#endif


#if 0

static void
ngx_garbage_collector_cycle(ngx_cycle_t *cycle, void *data)
{
    ngx_uint_t         i;
    ngx_gc_t           ctx;
    ngx_path_t       **path;
    ngx_event_t       *ev;

    ngx_worker_process_init(cycle, 0);

    ev = &cycle->read_events0[ngx_channel];

    ngx_accept_mutex = NULL;

    ngx_setproctitle("garbage collector");

#if 0
    ngx_add_timer(ev, 60 * 1000);
#endif

    for ( ;; ) {

        if (ngx_terminate || ngx_quit) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
            exit(0);
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }

        path = cycle->pathes.elts;
        for (i = 0; i < cycle->pathes.nelts; i++) {
            ctx.path = path[i];
            ctx.log = cycle->log;
            ctx.handler = path[i]->cleaner;

            ngx_collect_garbage(&ctx, &path[i]->name, 0);
        }

        ngx_add_timer(ev, 60 * 60 * 1000);

        ngx_process_events_and_timers(cycle);
    }
}

#endif
