
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setproctitle.h>


typedef pid_t       ngx_pid_t;

/* 无效的pid使用-1来标记 */
#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

typedef struct {
    ngx_pid_t           pid;            /* 进程id */
    int                 status;         /* 进程退出状态 主要在waitpid中进行处理 */
    ngx_socket_t        channel[2];     /* 进程socketpair创建的句柄 */

    ngx_spawn_proc_pt   proc;           /* 进程要执行的函数 */
    void               *data;           /* 进程所执行函数proc的参数 */
    char               *name;           /* 进程名字 */

    /* 进程的几个状态 bitfield 默认值是0 */
    unsigned            respawn:1;      // 自动重启标记
    unsigned            just_respawn:1; // 如果有该标记，广播命令时，不给该进程发送，仅清除该标记；用于重读配置
    unsigned            detached:1;     // detached标记，平滑升级时使用
    unsigned            exiting:1;      // 进程退出中标记
    unsigned            exited:1;       // 进程已经退出标记
} ngx_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


#define NGX_MAX_PROCESSES         1024 /* nginx中最大进程数 */

#define NGX_PROCESS_NORESPAWN     -1  // no re_spawn 子进程退出时 父进程不会再次重启
#define NGX_PROCESS_RESPAWN       -2  // 子进程异常退出时,父进程需要重启
#define NGX_PROCESS_JUST_RESPAWN  -3
#define NGX_PROCESS_DETACHED      -4  // 热代码替换，暂时估计是用于在不重启Nginx的情况下进行软件升级


#define ngx_getpid   getpid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;
extern ngx_socket_t   ngx_channel;
extern ngx_int_t      ngx_process_slot;
extern ngx_int_t      ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
