#ifndef PROC_INFO_H
#define PROC_INFO_H

#include <sys/types.h>

typedef struct cmdchain_struct {
    int array_pids[100];
    char *arr_cmdline[100];
    char *arr_proc_path[100];
    long long unsigned int start_time[100];
} cmd_chain_struct;

typedef struct proc_stat {
    int pid;
    char* comm;
    char state;
    int ppid;
    int pgid;
    int session;
    int tty_nr;
    int tpgid;
    unsigned int flags;
    long unsigned int minflt;
    long unsigned int cminflt;
    long unsigned int majflt;
    long unsigned int cmajflt;
    long unsigned int utime;
    long unsigned int stime;
    long int cutime;
    long int cstime;
    long int priority;
    long int nice;
    long int num_threads;
    long int itrealvalue;
    long long unsigned int starttime;
    long unsigned int vsize;
    long int rss;
    long unsigned int rsslim;
    long unsigned int startcode;
    long unsigned int endcode;
    long unsigned int startstack;
    long unsigned int kstkesp;
    long unsigned int kstkeip;
    long unsigned int signal;
    long unsigned int blocked;
    long unsigned int sigignore;
    long unsigned int sigcatch;
    long unsigned int wchan;
    long unsigned int nswap;
    long unsigned int cnswap;
    int exit_signal;
    int processor;
    unsigned int rt_priority;
    unsigned int policy;
    long long unsigned int delayacct_blkio_ticks;
    long unsigned int guest_time;
    long int cguest_time;
    long unsigned int start_data;
    long unsigned int end_data;
    long unsigned int start_brk;
    long unsigned int arg_start;
    long unsigned int arg_end;
    long unsigned int env_start;
    long unsigned int env_end;
    int exit_code;
} proc_stat;

char *read_cmdline(int pid);
char *read_proc_path(int pid);
proc_stat get_proc_stat(int pid);
long get_file_length(char *path);
void get_cmd_chain(int pid, cmd_chain_struct *chain_struct_info);

#endif
