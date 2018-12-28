
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>

/**
 * 如果一个struct定义在.c文件中 一般是为了这个.c文件自己使用 否则一般要定义在.h文件中
 */
typedef struct {
     int     signo;
     char   *signame;
     void  (*handler)(int signo);
} ngx_signal_t;



static void ngx_execute_proc(ngx_cycle_t *cycle, void *data);
static void ngx_signal_handler(int signo);
static void ngx_process_get_status(void);


int              ngx_argc;
char           **ngx_argv;
char           **ngx_os_argv;

/**
 * ngx_process_slot     进程的slot
 * ngx_channel          进程的管道
 * ngx_last_process     最后一个子进程的索引
 * ngx_processes        全局进程表 包含所有的存活的子进程
 */
ngx_int_t        ngx_process_slot;
ngx_socket_t     ngx_channel;
ngx_int_t        ngx_last_process;
ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];

// 所有的信号
ngx_signal_t  signals[] = {
    { ngx_signal_value(NGX_RECONFIGURE_SIGNAL),  // #define	SIGHUP	1	/* hangup */
      "SIG" ngx_value(NGX_RECONFIGURE_SIGNAL),   // "SIGHUP"
      ngx_signal_handler },

    { ngx_signal_value(NGX_REOPEN_SIGNAL),       // #define SIGUSR1 30	/* user defined signal 1 */
      "SIG" ngx_value(NGX_REOPEN_SIGNAL),        // "SIGUSR1"
      ngx_signal_handler },

    { ngx_signal_value(NGX_NOACCEPT_SIGNAL),     // #define SIGWINCH 28	/* window size changes */
      "SIG" ngx_value(NGX_NOACCEPT_SIGNAL),      // "SIGWINCH"
      ngx_signal_handler },

    { ngx_signal_value(NGX_TERMINATE_SIGNAL),    // #define	SIGTERM	15	/* software termination signal from kill */
      "SIG" ngx_value(NGX_TERMINATE_SIGNAL),     // SIGTERM
      ngx_signal_handler },

    { ngx_signal_value(NGX_SHUTDOWN_SIGNAL),     // #define	SIGQUIT	3	/* quit */
      "SIG" ngx_value(NGX_SHUTDOWN_SIGNAL),      //  "SIGQUIT"
      ngx_signal_handler },

    { ngx_signal_value(NGX_CHANGEBIN_SIGNAL),    // #define SIGUSR2 31	/* user defined signal 2 */
      "SIG" ngx_value(NGX_CHANGEBIN_SIGNAL),     // SIGUSR2
      ngx_signal_handler },

    { SIGALRM, "SIGALRM", ngx_signal_handler },

    { SIGINT, "SIGINT", ngx_signal_handler },

    { SIGIO, "SIGIO", ngx_signal_handler },

    { SIGCHLD, "SIGCHLD", ngx_signal_handler },

    { SIGPIPE, "SIGPIPE, SIG_IGN", SIG_IGN }, // TODO how does SIG_IGN do?
    // #define	SIG_IGN		(void (*)(int))1 意思是把‘1’强制类型转换为无返回值且具有一个整型参数的函数指针 如何使用呢？
    // 若信号句柄是SIG_DFL或SIG_IGN，则分别表示对捕获的信号采取忽略操作或者默认操作

    { 0, NULL, NULL }
};


/**
 * nginx在这里fork子进程
 *
 * @param cycle     全局配置
 * @param proc      子进程需要执行的函数
 * @param data      proc的参数
 * @param name      要创建的子进程的名字
 * @param respawn
 * @return
 */
ngx_pid_t
ngx_spawn_process(ngx_cycle_t *cycle, ngx_spawn_proc_pt proc, void *data,
    char *name, ngx_int_t respawn)
{
    u_long     on;
    ngx_pid_t  pid;
    ngx_int_t  s;   /* slot */

    /**
     * 1 首先找到要fork出来的子进程要放在进程表ngx_processes的哪个位置 用s记录(slot)
     */
    if (respawn >= 0) { /* 如果传进来的类型大于0 就是确定这个进程已经退出了 可以直接确定位置 */
        s = respawn;
    } else {
        // 这里说明所有的子进程都是紧挨着存放的
        for (s = 0; s < ngx_last_process; s++) {
            if (ngx_processes[s].pid == -1) {
                break;
            }
        }

        if (s == NGX_MAX_PROCESSES) { /* 最大进程数 报错 */
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "no more than %d processes can be spawned",
                          NGX_MAX_PROCESSES);
            return NGX_INVALID_PID;
        }
    }

    // 如果类型为NGX_PROCESS_DETACHED,则说明是热代码替换(热代码替换也是通过这个函数进行处理的),因此不需要新建socketpair。
    if (respawn != NGX_PROCESS_DETACHED) {

        /* Solaris 9 still has no AF_LOCAL */

        /**
         * 2 建立socketpair 用于进程间双向通讯
         */
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, ngx_processes[s].channel) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "socketpair() failed while spawning \"%s\"", name);
            return NGX_INVALID_PID;
        }

        /**
         * 同步与异步的理解
         * 同步与异步的重点在消息通知的方式上，也就是调用结果通知的方式。
         * 同步：当一个同步调用发出去后，调用者要一直等待调用结果的通知后，才能进行后续的执行。
         * 异步：当一个异步调用发出去后，调用者不能立即得到调用结果的返回。
         * 异步调用，要想获得结果，一般有两种方式：
         *      1、主动轮询异步调用的结果;
         *      2、被调用方通过callback来通知调用方调用结果。
         *
         * 阻塞与非阻塞的理解
         * 阻塞与非阻塞的重点在于进/线程等待消息时候的行为，也就是在等待消息的时候，当前进/线程是挂起状态，还是非挂起状态。
         *  - 阻塞:阻塞调用在发出去后，在消息返回之前，当前进/线程会被挂起，直到有消息返回，当前进/线程才会被激活
         *  - 非阻塞:非阻塞调用在发出去后，不会阻塞当前进/线程，而会立即返回
         *
         */
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "channel %d:%d",
                       ngx_processes[s].channel[0],
                       ngx_processes[s].channel[1]);
        // 设置非阻塞模式
        if (ngx_nonblocking(ngx_processes[s].channel[0]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (ngx_nonblocking(ngx_processes[s].channel[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        // 打开异步模式
        on = 1;
        if (ioctl(ngx_processes[s].channel[0], FIOASYNC, &on) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        // 设置异步io的所有者
        if (fcntl(ngx_processes[s].channel[0], F_SETOWN, ngx_pid) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        // 当exec后关闭句柄
        if (fcntl(ngx_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        /**
         * master进程是如何向worker进程发送消息的呢？
         * worker进程又是如何接收master发送过来的消息呢？就是使用的套接字 准确地说是socketpair。
         * 注意的是虽然套接字是双工的，但目前套接字仅用于master进程管理worker进程，
         * 而没用于worker发消息给master，或者worker进程间通信 (参考:《深入理解Nginx》).
         */
        // 设置当前的子进程的句柄
        ngx_channel = ngx_processes[s].channel[1];

    } else { // respawn == NGX_PROCESS_DETACHED
        ngx_processes[s].channel[0] = -1;
        ngx_processes[s].channel[1] = -1;
    }

    /**
    * 3 fork子进程 在子进程中执行传入的proc函数
    */
    ngx_process_slot = s; // 设置进程在进程表中的slot。

    pid = fork();
    switch (pid) {
    case -1:
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "fork() failed while spawning \"%s\"", name);
        ngx_close_channel(ngx_processes[s].channel, cycle->log);
        return NGX_INVALID_PID;

    case 0:
        // 子进程 执行传递进来的子进程函数 然后进入子进程轮转
        ngx_pid = ngx_getpid(); // ngx_pid设置为子进程的pid
        proc(cycle, data);
        break;

    default:
        break;
    }

    // 主进程继续维持全局信息
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);

    ngx_processes[s].pid = pid;
    ngx_processes[s].exited = 0;

    // 如果大于0,则说明我们确定了重启的子进程,因此下面的初始化就用已死的子进程的就够了。
    if (respawn >= 0) {
        return pid;
    }

    ngx_processes[s].proc = proc;
    ngx_processes[s].data = data;
    ngx_processes[s].name = name;
    ngx_processes[s].exiting = 0;

    //设置相关状态。
    switch (respawn) {

    case NGX_PROCESS_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_respawn = 0;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_JUST_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_respawn = 1;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_DETACHED:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_respawn = 0;
        ngx_processes[s].detached = 1;
        break;
    }

    if (s == ngx_last_process) {
        ngx_last_process++;
    }

    return pid;
}


ngx_pid_t
ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
{
    return ngx_spawn_process(cycle, ngx_execute_proc, ctx, ctx->name,
                             NGX_PROCESS_DETACHED);
}


static void
ngx_execute_proc(ngx_cycle_t *cycle, void *data)
{
    ngx_exec_ctx_t  *ctx = data;

    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}


ngx_int_t
ngx_init_signals(ngx_log_t *log)
{
    ngx_signal_t      *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = sig->handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "sigaction(%s) failed", sig->signame);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/**
 * 在nginx中,worker和master的交互,就是通过流管道以及信号,
 * 而master与外部的交互是通过信号来进行的
 *
 * @param signo
 */
void
ngx_signal_handler(int signo)
{
    char            *action;
    ngx_int_t        ignore;
    ngx_err_t        err;
    ngx_signal_t    *sig;

    ignore = 0;

    err = ngx_errno;

    // 首先得到当前的信号值
    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }

    ngx_time_update(0, 0);

    action = "";

    // 这里ngx_process在master和worker中赋值不同。
    switch (ngx_process) {
    // master中
    case NGX_PROCESS_MASTER:
    case NGX_PROCESS_SINGLE:
        switch (signo) {

        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            // 如果接受到quit信号,则准备退出进程。
            ngx_quit = 1;
            action = ", shutting down";
            break;

        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            // sigint信号
            ngx_terminate = 1;
            action = ", exiting";
            break;

        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            // winch信号,停止接受accept。
            ngx_noaccept = 1;
            action = ", stop accepting connections";
            break;

        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
            // sighup信号用来reconfig
            ngx_reconfigure = 1;
            action = ", reconfiguring";
            break;

        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            // 用户信号,用来reopen
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
            // 热代码替换
            if (getppid() > 1 || ngx_new_binary > 0) {

                /*
                 * Ignore the signal in the new binary if its parent is
                 * not the init process, i.e. the old binary's process
                 * is still running.  Or ingore the signal in the old binary's
                 * process if the new binary's process is already running.
                 */

                action = ", ignoring";
                ignore = 1;
                break;
            }
            // 正常情况下,需要热代码替换。设置标志位
            ngx_change_binary = 1;
            action = ", changing binary";
            break;

        case SIGALRM:
            break;

        case SIGIO:
            ngx_sigio = 1;
            break;

        case SIGCHLD:
            // 子进程已终止或退出,设置标记。
            ngx_reap = 1;
            break;
        }

        break;

    // worker的信号处理。worker的比较简单。
    case NGX_PROCESS_WORKER:
        switch (signo) {

        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            ngx_debug_quit = 1;
        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;

        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;

        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
        case SIGIO:
            action = ", ignoring";
            break;
        }

        break;
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "signal %d (%s) received%s", signo, sig->signame, action);

    if (ignore) {
        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
                      "the changing binary signal is ignored: "
                      "you should shutdown or terminate "
                      "before either old or new binary's process");
    }

    // 最终如果信号是sigchld,我们收割僵尸进程(用waitpid)。
    if (signo == SIGCHLD) {
        ngx_process_get_status();
    }

    ngx_set_errno(err);
}


static void
ngx_process_get_status(void)
{
    int              status;
    char            *process;
    ngx_pid_t        pid;
    ngx_err_t        err;
    ngx_int_t        i;
    ngx_uint_t       one;

    one = 0;

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = ngx_errno;

            if (err == NGX_EINTR) {
                continue;
            }

            if (err == NGX_ECHILD && one) {
                return;
            }

#if (NGX_SOLARIS)

            /*
             * Solaris always calls the signal handler for each exited process
             * despite waitpid() may be already called for this process
             */

            if (err == NGX_ECHILD) {
                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, errno,
                              "waitpid() failed");
                return;
            }

#endif

            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, errno,
                          "waitpid() failed");

            return;
        }


        if (ngx_accept_mutex_ptr) {

            /*
             * unlock the accept mutex if the abnormally exited process
             * held it
             */

            ngx_atomic_cmp_set(ngx_accept_mutex_ptr, pid, 0);
        }


        one = 1;
        process = "unknown process";

        for (i = 0; i < ngx_last_process; i++) {
            if (ngx_processes[i].pid == pid) {
                ngx_processes[i].status = status;
                ngx_processes[i].exited = 1;
                process = ngx_processes[i].name;
                break;
            }
        }

        if (WTERMSIG(status)) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d%s",
                          process, pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");

        } else {
            ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                          "%s %P exited with code %d",
                          process, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && ngx_processes[i].respawn) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                        "%s %P exited with fatal code %d and could not respawn",
                        process, pid, WEXITSTATUS(status));
            ngx_processes[i].respawn = 0;
        }
    }
}


void
ngx_debug_point(void)
{
    ngx_core_conf_t  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    switch (ccf->debug_points) {

    case NGX_DEBUG_POINTS_STOP:
        raise(SIGSTOP);
        break;

    case NGX_DEBUG_POINTS_ABORT:
        ngx_abort();
    }
}
