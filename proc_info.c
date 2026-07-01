#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include "proc_info.h"
#include "dns_log.h"

long get_file_length(char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        dns_log(LOG_WARNING, "open %s error", path);
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fclose(fp);
    return len < 0 ? 0 : len;
}

char *read_proc_path(int pid) {
    char *buf = malloc(1024);
    if (!buf) {
        dns_log(LOG_ERROR, "malloc failed in read_proc_path");
        return NULL;
    }
    memset(buf, 0, 1024);

    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);

    ssize_t n = readlink(link_path, buf, 1023);
    if (n <= 0) {
        dns_log(LOG_WARNING, "readlink failed for %s", link_path);
    }
    return buf;
}

char *read_cmdline(int pid) {
    char cmd_path[64];
    snprintf(cmd_path, sizeof(cmd_path), "/proc/%d/cmdline", pid);

    long flen = get_file_length(cmd_path);
    if (flen <= 0) {
        char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }

    FILE *fp = fopen(cmd_path, "rb");
    if (!fp) {
        dns_log(LOG_WARNING, "open %s error", cmd_path);
        return NULL;
    }

    char *buf = malloc(flen + 1);
    if (!buf) {
        fclose(fp);
        dns_log(LOG_ERROR, "malloc failed in read_cmdline");
        return NULL;
    }

    size_t nread = fread(buf, 1, (size_t)flen, fp);
    fclose(fp);
    buf[nread] = '\0';

    for (size_t i = 0; i < nread; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }
    while (nread > 0 && buf[nread-1] == ' ') {
        buf[--nread] = '\0';
    }

    return buf;
}

proc_stat get_proc_stat(int Pid) {
    proc_stat stat;
    memset(&stat, 0, sizeof(stat));

    char stat_path[32];
    if (Pid != -1) {
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", Pid);
    } else {
        snprintf(stat_path, sizeof(stat_path), "/proc/self/stat");
    }

    FILE *f = fopen(stat_path, "r");
    if (!f) {
        dns_log(LOG_WARNING, "open stat file error, pid:%d", Pid);
        return stat;
    }

    char line[4096];
    if (fgets(line, sizeof(line), f) == NULL) {
        fclose(f);
        return stat;
    }
    fclose(f);

    char *first_paren = strchr(line, '(');
    char *last_paren = strrchr(line, ')');
    if (!first_paren || !last_paren || last_paren <= first_paren) {
        return stat;
    }

    static __thread char comm_buf[256];
    size_t comm_len = last_paren - first_paren - 1;
    if (comm_len >= sizeof(comm_buf)) comm_len = sizeof(comm_buf) - 1;
    memcpy(comm_buf, first_paren + 1, comm_len);
    comm_buf[comm_len] = '\0';
    stat.comm = comm_buf;

    int pid_val = 0;
    if (sscanf(line, "%d ", &pid_val) == 1) {
        stat.pid = pid_val;
    }

    sscanf(last_paren + 1,
        " %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %d",
        &stat.state, &stat.ppid, &stat.pgid, &stat.session, &stat.tty_nr, &stat.tpgid,
        &stat.flags, &stat.minflt, &stat.cminflt, &stat.majflt, &stat.cmajflt,
        &stat.utime, &stat.stime, &stat.cutime, &stat.cstime, &stat.priority, &stat.nice,
        &stat.num_threads, &stat.itrealvalue, &stat.starttime, &stat.vsize, &stat.rss,
        &stat.rsslim, &stat.startcode, &stat.endcode, &stat.startstack, &stat.kstkesp,
        &stat.kstkeip, &stat.signal, &stat.blocked, &stat.sigignore, &stat.sigcatch,
        &stat.wchan, &stat.nswap, &stat.cnswap, &stat.exit_signal, &stat.processor,
        &stat.rt_priority, &stat.policy, &stat.delayacct_blkio_ticks, &stat.guest_time,
        &stat.cguest_time, &stat.start_data, &stat.end_data, &stat.start_brk,
        &stat.arg_start, &stat.arg_end, &stat.env_start, &stat.env_end, &stat.exit_code);

    return stat;
}

void get_cmd_chain(int pid, cmd_chain_struct *chain_struct_info) {
    int array_ppid[100] = {0};
    int i = 0;

    proc_stat stat_info = get_proc_stat(pid);

    while (stat_info.ppid != 0 && i < 100) {
        array_ppid[i] = stat_info.pid;
        chain_struct_info->array_pids[i] = stat_info.pid;
        chain_struct_info->start_time[i] = stat_info.starttime / sysconf(_SC_CLK_TCK);
        stat_info = get_proc_stat(stat_info.ppid);
        i++;
    }
    array_ppid[i] = stat_info.pid;
    chain_struct_info->array_pids[i] = stat_info.pid;
    chain_struct_info->start_time[i] = stat_info.starttime / sysconf(_SC_CLK_TCK);

    for (i = 0; i < 100; i++) {
        if (array_ppid[i] == 0) break;
        chain_struct_info->arr_cmdline[i] = read_cmdline(array_ppid[i]);
        chain_struct_info->arr_proc_path[i] = read_proc_path(array_ppid[i]);
    }
}
