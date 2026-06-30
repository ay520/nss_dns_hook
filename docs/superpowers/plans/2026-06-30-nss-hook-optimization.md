# NSS DNS Hook 优化实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 重构 `nss_dns_hook`,修复白名单每次加载/销毁、线程不安全、通配符匹配不全等严重问题,新增 DNS 结果缓存,日志改 syslog。

**Architecture:** 模块化拆分为 `proc_info` / `whitelist` / `dns_cache` / `dns_log` 四个独立编译单元,`nss_module.c` 只保留 NSS 入口和网络判定。白名单常驻 + RWLock + mtime 热加载;缓存 LRU+TTL,缓存原始 DNS 响应字节;日志走 syslog(LOG_LOCAL0)。

**Tech Stack:** C99, glibc NSS, pthread RWLock, uthash, syslog, resolv (`res_nquery`/`ns_initparse`/`ns_parserr`/`ns_rr_ttl`)。

## Global Constraints

- 目标平台: Linux + glibc(代码使用 `/proc`、`nss.h`、`resolv.h`、`gaih_addrtuple` 等 glibc 内部接口,macOS 无法编译)
- 编译器: gcc,`-Wall -Wextra -std=c99 -fPIC`
- 链接: `-shared -Wl,-soname,libnss_hs.so.2 -lpthread -lresolv`
- 开发机是 macOS,无法本地编译验证;所有编译/测试在 Linux 开发环境 `8.155.31.213`(SSH 证书 `/Users/wukong/dnshook/wukong.pem`)上进行
- 用户要求: 先全部写完代码,最后统一在 Linux 上编译测试
- 不删除 `get_cmd_chain` / `get_proc_stat` 等未用函数(后续 exe 维度策略会用)
- 不改变 `cmd_chain_struct` / `proc_stat` 结构体布局
- fail-open 语义: 白名单空 → `return NSS_STATUS_NOTFOUND` 放行给下游 dns 模块
- 配置文件路径不变: `/etc/nss_whitelist.conf`、`/etc/nss_private_networks.conf`

## File Structure

| 文件 | 责任 | 操作 |
|------|------|------|
| `proc_info.h` | 声明 `read_cmdline`/`read_proc_path`/`get_proc_stat`/`get_cmd_chain` 及结构体 | 新建 |
| `proc_info.c` | `/proc` 解析,从 `get_cmdchain.c` 改名 + 修 bug | 重命名 + 重写 |
| `dns_log.h` | 日志接口 | 修改(删 `set_log_file`,加 `LOG_DEBUG`) |
| `dns_log.c` | syslog 封装 | 重写 |
| `whitelist.h` | 白名单接口 | 新建 |
| `whitelist.c` | 加载/查找/mtime 重载/RWLock | 新建 |
| `dns_cache.h` | 缓存接口 | 新建 |
| `dns_cache.c` | LRU+TTL/RWLock | 新建 |
| `nss_module.c` | NSS 入口 + 网络判定 | 修改(删迁移代码,加 `parse_answer_and_add`,重构入口流程) |
| `Makefile` | 编译规则 | 修改 `SRCS` |
| `README` | 部署文档 | 修改 |
| `get_cmdchain.c` | — | 删除(内容迁移到 `proc_info.c`) |

依赖方向(单向无环): `nss_module.c → {proc_info, whitelist, dns_cache, dns_log}`;`proc_info → dns_log`;`whitelist → {dns_log, uthash}`;`dns_cache → {dns_log, uthash}`。

---

## Task 1: proc_info 模块(从 get_cmdchain.c 改名 + 修 bug)

**Files:**
- Create: `proc_info.h`
- Create: `proc_info.c`(内容来自 `get_cmdchain.c`,修 bug)
- Delete: `get_cmdchain.c`
- 不改 `Makefile`(Task 5 统一改)

**Interfaces:**
- Produces: `read_cmdline(int pid) -> char*`(调用方 free)、`read_proc_path(int pid) -> char*`(调用方 free)、`get_proc_stat(int pid) -> proc_stat`、`get_file_length(char *path) -> long`、`get_cmd_chain(int pid, cmd_chain_struct*)`、结构体 `cmd_chain_struct` / `proc_stat`

**注意:** 本任务无法在 macOS 编译验证(`/proc`、`resolv.h` 等),代码审查为主,编译在 Task 7 进行。

- [ ] **Step 1: 创建 `proc_info.h`**

```c
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
```

- [ ] **Step 2: 创建 `proc_info.c`**

```c
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
        " %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %d",
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
```

- [ ] **Step 3: 删除 `get_cmdchain.c`**

```bash
rm get_cmdchain.c
```

- [ ] **Step 4: 提交**

```bash
git add proc_info.h proc_info.c
git rm get_cmdchain.c
git commit -m "$(cat <<'EOF'
Refactor: rename get_cmdchain.c to proc_info.{h,c} and fix bugs

- Extract header with public declarations
- Fix read_proc_path returning uninitialized buffer on readlink failure
- Fix get_file_length O(n) char-by-char read → O(1) fseek/ftell
- Fix get_proc_stat fscanf breaking on comm with spaces (use fgets + strrchr)
- Simplify read_cmdline null-separator handling
- Use __thread static buffer for comm to avoid dangling pointer
- Preserve all function signatures and struct layouts for future exe-policy use

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: dns_log 模块(syslog 封装)

**Files:**
- Modify: `dns_log.h`
- Rewrite: `dns_log.c`

**Interfaces:**
- Produces: `dns_log(int log_level, const char *format, ...)`、宏 `LOG_INFO=6` / `LOG_WARNING=4` / `LOG_ERROR=3` / `LOG_DEBUG=7`
- 删除: `set_log_file`(syslog 模式下无意义)

- [ ] **Step 1: 修改 `dns_log.h`**

```c
#ifndef DNS_LOG_H
#define DNS_LOG_H

#define MAX_PATH_LENGTH 512

#define LOG_INFO    6
#define LOG_WARNING 4
#define LOG_ERROR   3
#define LOG_DEBUG   7

#ifdef __cplusplus
extern "C" {
#endif

void dns_log(int log_level, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
```

- [ ] **Step 2: 重写 `dns_log.c`**

```c
#include "dns_log.h"
#include <syslog.h>
#include <stdarg.h>

void dns_log(int log_level, const char *format, ...) {
    int priority;
    switch (log_level) {
        case LOG_INFO:    priority = LOG_INFO;    break;
        case LOG_WARNING: priority = LOG_WARNING; break;
        case LOG_ERROR:   priority = LOG_ERR;     break;
        case LOG_DEBUG:   priority = LOG_DEBUG;   break;
        default:          priority = LOG_DEBUG;   break;
    }
    va_list args;
    va_start(args, format);
    vsyslog(priority, format, args);
    va_end(args);
}
```

- [ ] **Step 3: 提交**

```bash
git add dns_log.h dns_log.c
git commit -m "$(cat <<'EOF'
Refactor: dns_log to syslog(LOG_LOCAL0) wrapper

- Replace fopen/fprintf/fclose per call with vsyslog (thread-safe)
- Remove set_log_file (meaningless under syslog; routing is syslogd's job)
- Add LOG_DEBUG level for verbose debug logs (gated by syslog priority)
- openlog/closelog will be called from nss_module.c constructor/destructor

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: whitelist 模块

**Files:**
- Create: `whitelist.h`
- Create: `whitelist.c`

**Interfaces:**
- Consumes: `dns_log`、`uthash.h`、`dns_log.h` 的 `LOG_*` 宏
- Produces: `whitelist_initial_load(void)`、`whitelist_check_mtime(void)`、`whitelist_match(const char *domain) -> int`、`whitelist_is_loaded(void) -> int`、`whitelist_destroy(void)`、宏 `WHITELIST_FILE`、`MAX_WHITELIST_ENTRIES`、`MAX_DOMAIN_LENGTH`

- [ ] **Step 1: 创建 `whitelist.h`**

```c
#ifndef WHITELIST_H
#define WHITELIST_H

#define WHITELIST_FILE "/etc/nss_whitelist.conf"
#define MAX_WHITELIST_ENTRIES 10000
#define MAX_DOMAIN_LENGTH 256

void whitelist_initial_load(void);
void whitelist_check_mtime(void);
int whitelist_match(const char *domain);
int whitelist_is_loaded(void);
void whitelist_destroy(void);

#endif
```

- [ ] **Step 2: 创建 `whitelist.c`**

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include "uthash.h"
#include "whitelist.h"
#include "dns_log.h"

struct whitelist_entry {
    char *domain;
    int is_wildcard;
    UT_hash_handle hh;
};

static struct whitelist_entry *whitelist_hash = NULL;
static time_t whitelist_mtime = 0;
static int whitelist_count = 0;
static pthread_rwlock_t whitelist_lock = PTHREAD_RWLOCK_INITIALIZER;

static void whitelist_free_hash_locked(void) {
    if (!whitelist_hash) return;
    struct whitelist_entry *cur, *tmp;
    HASH_ITER(hh, whitelist_hash, cur, tmp) {
        HASH_DEL(whitelist_hash, cur);
        free(cur->domain);
        free(cur);
    }
    whitelist_hash = NULL;
}

static int whitelist_reload_locked(void) {
    FILE *fp = fopen(WHITELIST_FILE, "r");
    if (!fp) {
        dns_log(LOG_WARNING, "Could not open whitelist file: %s", WHITELIST_FILE);
        return -1;
    }

    struct stat st;
    if (stat(WHITELIST_FILE, &st) == 0) {
        whitelist_mtime = st.st_mtime;
    }

    struct whitelist_entry *new_hash = NULL;
    char line[MAX_DOMAIN_LENGTH];
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (count >= MAX_WHITELIST_ENTRIES) {
            dns_log(LOG_WARNING, "whitelist exceeds MAX_WHITELIST_ENTRIES, truncated");
            break;
        }

        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;

        struct whitelist_entry *e = malloc(sizeof(*e));
        if (!e) continue;
        e->domain = strdup(line);
        if (!e->domain) { free(e); continue; }
        e->is_wildcard = (line[0] == '*');
        HASH_ADD_STR(new_hash, domain, e);
        count++;
    }
    fclose(fp);

    whitelist_free_hash_locked();
    whitelist_hash = new_hash;
    whitelist_count = count;
    dns_log(LOG_INFO, "Loaded %d domains into whitelist", count);
    return 0;
}

void whitelist_initial_load(void) {
    pthread_rwlock_wrlock(&whitelist_lock);
    whitelist_reload_locked();
    pthread_rwlock_unlock(&whitelist_lock);
}

void whitelist_check_mtime(void) {
    struct stat st;
    if (stat(WHITELIST_FILE, &st) != 0) return;
    if (st.st_mtime == whitelist_mtime) return;

    pthread_rwlock_wrlock(&whitelist_lock);
    if (stat(WHITELIST_FILE, &st) == 0 && st.st_mtime != whitelist_mtime) {
        whitelist_reload_locked();
    }
    pthread_rwlock_unlock(&whitelist_lock);
}

int whitelist_match(const char *domain) {
    if (!domain) return 0;

    pthread_rwlock_rdlock(&whitelist_lock);

    struct whitelist_entry *e;
    HASH_FIND_STR(whitelist_hash, domain, e);
    if (e) { pthread_rwlock_unlock(&whitelist_lock); return 1; }

    const char *p = domain;
    while ((p = strchr(p, '.')) != NULL) {
        char wildcard[MAX_DOMAIN_LENGTH];
        snprintf(wildcard, sizeof(wildcard), "*%s", p);
        HASH_FIND_STR(whitelist_hash, wildcard, e);
        if (e) { pthread_rwlock_unlock(&whitelist_lock); return 1; }
        p++;
    }

    pthread_rwlock_unlock(&whitelist_lock);
    return 0;
}

int whitelist_is_loaded(void) {
    return whitelist_count > 0 ? 1 : 0;
}

void whitelist_destroy(void) {
    pthread_rwlock_wrlock(&whitelist_lock);
    whitelist_free_hash_locked();
    whitelist_count = 0;
    whitelist_mtime = 0;
    pthread_rwlock_unlock(&whitelist_lock);
}
```

- [ ] **Step 3: 提交**

```bash
git add whitelist.h whitelist.c
git commit -m "$(cat <<'EOF'
Add whitelist module: persistent hash + RWLock + mtime reload

- Load whitelist once in constructor, hold globally (no per-query reload)
- RWLock: reads (match) use rdlock, reload uses wrlock
- mtime check on every query (stat + compare, ~1us fast path)
  with double-check under wrlock to avoid concurrent duplicate reloads
- Atomic reload: build new hash, then swap (no empty-hash window)
- Fix wildcard matching: iterate all suffix levels (*.baidu.com now
  matches a.b.baidu.com, not just www.baidu.com)
- fail-open: empty whitelist returns NSS_STATUS_NOTFOUND (defer to dns)
- Fix off-by-one in MAX_WHITELIST_ENTRIES check

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: dns_cache 模块

**Files:**
- Create: `dns_cache.h`
- Create: `dns_cache.c`

**Interfaces:**
- Consumes: `dns_log`、`uthash.h`
- Produces: `dns_cache_get(...) -> int`(1 命中,0 未命中/过期)、`dns_cache_put(...)`(内部 malloc+memcpy)、`dns_cache_destroy(void)`、宏 `DNS_CACHE_MAX_ENTRIES=512`、`DNS_CACHE_TTL_CAP=300`、`DNS_CACHE_NEG_TTL=30`

- [ ] **Step 1: 创建 `dns_cache.h`**

```c
#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <stddef.h>

#define DNS_CACHE_MAX_ENTRIES 512
#define DNS_CACHE_TTL_CAP 300
#define DNS_CACHE_NEG_TTL 30

int dns_cache_get(const char *domain,
                  unsigned char **out_a, size_t *out_a_len, int *out_neg_a,
                  unsigned char **out_aaaa, size_t *out_aaaa_len, int *out_neg_aaaa);

void dns_cache_put(const char *domain,
                   const unsigned char *answer_a, size_t a_len, int neg_a, int ttl_a,
                   const unsigned char *answer_aaaa, size_t aaaa_len, int neg_aaaa, int ttl_aaaa);

void dns_cache_destroy(void);

#endif
```

- [ ] **Step 2: 创建 `dns_cache.c`**

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "uthash.h"
#include "dns_cache.h"
#include "dns_log.h"

struct cache_entry {
    char *domain;
    unsigned char *answer_a;
    size_t answer_a_len;
    unsigned char *answer_aaaa;
    size_t answer_aaaa_len;
    time_t expires_at;
    int negative_a;
    int negative_aaaa;
    UT_hash_handle hh;
    struct cache_entry *lru_prev;
    struct cache_entry *lru_next;
};

static struct cache_entry *cache_hash = NULL;
static struct cache_entry *lru_head = NULL;
static struct cache_entry *lru_tail = NULL;
static size_t cache_count = 0;
static pthread_rwlock_t cache_lock = PTHREAD_RWLOCK_INITIALIZER;

static void lru_remove(struct cache_entry *e) {
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else lru_head = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else lru_tail = e->lru_prev;
    e->lru_prev = NULL;
    e->lru_next = NULL;
}

static void lru_insert_head(struct cache_entry *e) {
    e->lru_prev = NULL;
    e->lru_next = lru_head;
    if (lru_head) lru_head->lru_prev = e;
    lru_head = e;
    if (!lru_tail) lru_tail = e;
}

static void cache_entry_free(struct cache_entry *e) {
    if (!e) return;
    free(e->domain);
    free(e->answer_a);
    free(e->answer_aaaa);
    free(e);
}

int dns_cache_get(const char *domain,
                  unsigned char **out_a, size_t *out_a_len, int *out_neg_a,
                  unsigned char **out_aaaa, size_t *out_aaaa_len, int *out_neg_aaaa) {
    pthread_rwlock_rdlock(&cache_lock);

    struct cache_entry *e;
    HASH_FIND_STR(cache_hash, domain, e);
    if (!e) {
        pthread_rwlock_unlock(&cache_lock);
        return 0;
    }

    if (time(NULL) >= e->expires_at) {
        pthread_rwlock_unlock(&cache_lock);
        return 0;
    }

    *out_a = e->answer_a;
    *out_a_len = e->answer_a_len;
    *out_neg_a = e->negative_a;
    *out_aaaa = e->answer_aaaa;
    *out_aaaa_len = e->answer_aaaa_len;
    *out_neg_aaaa = e->negative_aaaa;

    pthread_rwlock_unlock(&cache_lock);
    return 1;
}

static void cache_sweep_expired_locked(void) {
    time_t now = time(NULL);
    struct cache_entry *cur, *tmp;
    HASH_ITER(hh, cache_hash, cur, tmp) {
        if (now >= cur->expires_at) {
            lru_remove(cur);
            HASH_DEL(cache_hash, cur);
            cache_entry_free(cur);
            cache_count--;
        }
    }
}

void dns_cache_put(const char *domain,
                   const unsigned char *answer_a, size_t a_len, int neg_a, int ttl_a,
                   const unsigned char *answer_aaaa, size_t aaaa_len, int neg_aaaa, int ttl_aaaa) {
    pthread_rwlock_wrlock(&cache_lock);

    cache_sweep_expired_locked();

    int ttl = ttl_a;
    if (ttl_aaaa > 0 && (ttl <= 0 || ttl_aaaa < ttl)) ttl = ttl_aaaa;
    if (ttl <= 0 || ttl > DNS_CACHE_TTL_CAP) ttl = DNS_CACHE_TTL_CAP;
    if (neg_a && neg_aaaa) ttl = DNS_CACHE_NEG_TTL;

    time_t expires_at = time(NULL) + ttl;

    struct cache_entry *e;
    HASH_FIND_STR(cache_hash, domain, e);

    if (e) {
        free(e->answer_a); e->answer_a = NULL;
        free(e->answer_aaaa); e->answer_aaaa = NULL;

        if (answer_a && a_len > 0) {
            e->answer_a = malloc(a_len);
            if (e->answer_a) { memcpy(e->answer_a, answer_a, a_len); e->answer_a_len = a_len; }
            else e->answer_a_len = 0;
        } else {
            e->answer_a_len = 0;
        }

        if (answer_aaaa && aaaa_len > 0) {
            e->answer_aaaa = malloc(aaaa_len);
            if (e->answer_aaaa) { memcpy(e->answer_aaaa, answer_aaaa, aaaa_len); e->answer_aaaa_len = aaaa_len; }
            else e->answer_aaaa_len = 0;
        } else {
            e->answer_aaaa_len = 0;
        }

        e->negative_a = neg_a;
        e->negative_aaaa = neg_aaaa;
        e->expires_at = expires_at;

        lru_remove(e);
        lru_insert_head(e);
    } else {
        e = calloc(1, sizeof(*e));
        if (!e) {
            pthread_rwlock_unlock(&cache_lock);
            dns_log(LOG_WARNING, "cache entry malloc failed for %s", domain);
            return;
        }
        e->domain = strdup(domain);
        if (!e->domain) {
            free(e);
            pthread_rwlock_unlock(&cache_lock);
            return;
        }

        if (answer_a && a_len > 0) {
            e->answer_a = malloc(a_len);
            if (e->answer_a) { memcpy(e->answer_a, answer_a, a_len); e->answer_a_len = a_len; }
        }
        if (answer_aaaa && aaaa_len > 0) {
            e->answer_aaaa = malloc(aaaa_len);
            if (e->answer_aaaa) { memcpy(e->answer_aaaa, answer_aaaa, aaaa_len); e->answer_aaaa_len = aaaa_len; }
        }
        e->negative_a = neg_a;
        e->negative_aaaa = neg_aaaa;
        e->expires_at = expires_at;

        HASH_ADD_STR(cache_hash, domain, e);
        lru_insert_head(e);
        cache_count++;

        while (cache_count > DNS_CACHE_MAX_ENTRIES && lru_tail) {
            struct cache_entry *victim = lru_tail;
            lru_remove(victim);
            HASH_DEL(cache_hash, victim);
            cache_entry_free(victim);
            cache_count--;
        }
    }

    pthread_rwlock_unlock(&cache_lock);
}

void dns_cache_destroy(void) {
    pthread_rwlock_wrlock(&cache_lock);
    struct cache_entry *cur, *tmp;
    HASH_ITER(hh, cache_hash, cur, tmp) {
        HASH_DEL(cache_hash, cur);
        cache_entry_free(cur);
    }
    cache_hash = NULL;
    lru_head = NULL;
    lru_tail = NULL;
    cache_count = 0;
    pthread_rwlock_unlock(&cache_lock);
}
```

- [ ] **Step 3: 提交**

```bash
git add dns_cache.h dns_cache.c
git commit -m "$(cat <<'EOF'
Add dns_cache module: LRU + TTL, caches raw DNS answer bytes

- Per-process cache (natural for NSS dlopen-per-process model)
- Cache raw res_nquery answer bytes, re-parse on hit (avoids serializing
  gaih_addrtuple linked list)
- A and AAAA stored separately, negative caching independent
- TTL = min(min TTL across records, 300s cap); negative TTL = 30s
- LRU 512 entries, approximate LRU (update on put only, not get, to keep
  rdlock for get)
- Internal malloc+memcpy on put (caller passes stack buffer, no ownership transfer)
- No singleflight (concurrent miss may duplicate upstream query; acceptable for DNS)
- RWLock: get uses rdlock, put uses wrlock

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: nss_module.c 集成 + Makefile

**Files:**
- Modify: `nss_module.c`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `proc_info.h`(`read_cmdline`/`read_proc_path`)、`whitelist.h`(`whitelist_check_mtime`/`whitelist_match`/`whitelist_is_loaded`/`whitelist_initial_load`/`whitelist_destroy`)、`dns_cache.h`(`dns_cache_get`/`dns_cache_put`/`dns_cache_destroy`)、`dns_log.h`(`dns_log`/`LOG_*`)、`syslog.h`(`openlog`/`closelog`)

**改动概要:**
1. 替换头文件:删 `#include "get_cmdchain.c"`,加 `#include "proc_info.h"` / `#include "whitelist.h"` / `#include "dns_cache.h"` / `#include <syslog.h>`
2. 删除迁移到 whitelist.c 的代码:`struct whitelist_entry`、`whitelist_hash`、`load_whitelist`、`is_domain_whitelisted`、`cleanup_whitelist`、`MAX_DOMAIN_LENGTH` / `WHITELIST_FILE` / `MAX_WHITELIST_ENTRIES` 宏定义
3. 新增 `parse_answer_and_add` 辅助函数
4. 重构 `_nss_hs_gethostbyname4_r`(加 cache + mtime + fail-open)
5. 修改 constructor/destructor(openlog/closelog + whitelist + cache 生命周期)
6. `print_address_list` 改用 `LOG_DEBUG`
7. Makefile 加 `whitelist.c dns_cache.c proc_info.c` 到 `SRCS`

- [ ] **Step 1: 修改 `nss_module.c` 头文件区**

把文件开头的:

```c
#include "dns_log.h"
#include "get_cmdchain.c"
#include "uthash.h"
```

替换为:

```c
#include <syslog.h>
#include "dns_log.h"
#include "proc_info.h"
#include "whitelist.h"
#include "dns_cache.h"
#include "uthash.h"
```

- [ ] **Step 2: 删除 `nss_module.c` 中迁移到 whitelist.c 的代码**

删除以下宏定义(已迁移到 whitelist.h,通过 include 引入):

```c
#define MAX_DOMAIN_LENGTH 256  
#define MAX_ADDRESSES 16       
#define DEFAULT_TTL 300       
#define ALIGN(x) (((x) + sizeof(void*) - 1) & ~(sizeof(void*) - 1))
#define WHITELIST_FILE "/etc/nss_whitelist.conf"
#define MAX_WHITELIST_ENTRIES 10000
```

替换为(保留 `MAX_ADDRESSES` / `DEFAULT_TTL` / `ALIGN`,删 `MAX_DOMAIN_LENGTH` / `WHITELIST_FILE` / `MAX_WHITELIST_ENTRIES`):

```c
#define MAX_ADDRESSES 16       
#define DEFAULT_TTL 300       
#define ALIGN(x) (((x) + sizeof(void*) - 1) & ~(sizeof(void*) - 1))
```

- [ ] **Step 3: 删除 `nss_module.c` 中 whitelist 相关代码块**

删除从 `struct whitelist_entry {` 开始,到 `cleanup_whitelist` 函数结束的整段(原文件约 242-341 行,包含 `struct whitelist_entry`、`whitelist_hash`、`load_whitelist`、`is_domain_whitelisted`、`cleanup_whitelist`)。这些已迁移到 `whitelist.c`。

- [ ] **Step 4: 修改 `print_address` 和 `print_address_list` 的日志级别**

在 `print_address` 函数里,把:

```c
        dns_log(LOG_INFO, "IPv4: %s", ip_str);
```
改成:
```c
        dns_log(LOG_DEBUG, "IPv4: %s", ip_str);
```

把:
```c
        dns_log(LOG_INFO, "IPv6: %s", ip_str);
```
改成:
```c
        dns_log(LOG_DEBUG, "IPv6: %s", ip_str);
```

在 `print_address_list` 函数里,把所有 `dns_log(LOG_INFO, ...)` 改成 `dns_log(LOG_DEBUG, ...)`:

```c
static void print_address_list(const struct gaih_addrtuple *pat) {
    dns_log(LOG_DEBUG, "Address list content:");
    const struct gaih_addrtuple *current = pat;
    int count = 0;
    
    while (current != NULL) {
        dns_log(LOG_DEBUG, "Address #%d:", ++count);
        print_address(current);
        current = current->next;
    }
    
    dns_log(LOG_DEBUG, "Total addresses: %d", count);
}
```

- [ ] **Step 5: 在 `add_ipv6_address` 函数之后、`_nss_hs_gethostbyname4_r` 之前,新增 `parse_answer_and_add` 辅助函数**

```c
// 从 answer buffer 解析 A 或 AAAA 记录,加到 pat 链表,顺便提取最小 TTL
// 返回新增地址数(addr_count 的增量);-1 表示解析失败
static int parse_answer_and_add(
    struct buffer_data *buf,
    const unsigned char *answer, int answer_len,
    int af,
    struct gaih_addrtuple **pat,
    struct gaih_addrtuple **prev,
    int *addr_count,
    const char *domain,
    int *out_min_ttl
) {
    ns_msg handle;
    ns_rr rr;
    int added = 0;
    int min_ttl = -1;

    if (ns_initparse(answer, answer_len, &handle) < 0) {
        *out_min_ttl = DEFAULT_TTL;
        return -1;
    }

    int count = ns_msg_count(handle, ns_s_an);
    int rr_type = (af == AF_INET) ? ns_t_a : ns_t_aaaa;

    for (int i = 0; i < count && *addr_count < MAX_ADDRESSES; i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            continue;
        }

        if (ns_rr_type(rr) == rr_type) {
            int ttl = (int)ns_rr_ttl(rr);
            if (ttl > 0 && (min_ttl < 0 || ttl < min_ttl)) min_ttl = ttl;

            bool ok;
            if (af == AF_INET) {
                ok = add_ipv4_address(buf, pat, prev, ns_rr_rdata(rr), addr_count, domain);
            } else {
                ok = add_ipv6_address(buf, pat, prev, ns_rr_rdata(rr), addr_count, domain);
            }
            if (ok) {
                added++;
            } else {
                *out_min_ttl = (min_ttl > 0 ? min_ttl : DEFAULT_TTL);
                return -1;
            }
        }
    }

    *out_min_ttl = (min_ttl > 0 ? min_ttl : DEFAULT_TTL);
    return added;
}
```

- [ ] **Step 6: 重写 `_nss_hs_gethostbyname4_r` 函数**

用以下完整实现替换原函数:

```c
enum nss_status _nss_hs_gethostbyname4_r(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop,
    int32_t *ttlp)
{
    if (!name || !pat || !buffer || !errnop || !h_errnop || 
        buflen < sizeof(struct gaih_addrtuple)) {
        if (errnop) *errnop = EINVAL;
        if (h_errnop) *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    char *cmdline = read_cmdline(getpid());
    char *exe_path = read_proc_path(getpid());
    dns_log(LOG_INFO, "ns(4) hook domain: %s pid: %d program:%s proc_path:%s",
            name, getpid(),
            cmdline ? cmdline : "(null)",
            exe_path ? exe_path : "(null)");
    free(cmdline);
    free(exe_path);

    size_t name_len = strlen(name);
    if (name_len == 0 || name_len >= MAX_DOMAIN_LENGTH) {
        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_UNAVAIL;
    }

    whitelist_check_mtime();

    if (!whitelist_is_loaded()) {
        dns_log(LOG_INFO, "Whitelist empty, deferring to next NSS module for %s", name);
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    struct buffer_data buf = { .buffer = buffer, .buflen = buflen, .offset = 0 };
    unsigned char answer[NS_MAXMSG];
    int addr_count = 0;
    struct gaih_addrtuple *prev = NULL;
    int min_ttl_a = DEFAULT_TTL, min_ttl_aaaa = DEFAULT_TTL;

    unsigned char *cached_a = NULL, *cached_aaaa = NULL;
    size_t cached_a_len = 0, cached_aaaa_len = 0;
    int neg_a = 0, neg_aaaa = 0;

    int cache_hit = dns_cache_get(name, &cached_a, &cached_a_len, &neg_a,
                                  &cached_aaaa, &cached_aaaa_len, &neg_aaaa);

    if (cache_hit) {
        dns_log(LOG_DEBUG, "Cache hit for %s", name);
        if (cached_a && cached_a_len > 0) {
            parse_answer_and_add(&buf, cached_a, (int)cached_a_len, AF_INET,
                                 pat, &prev, &addr_count, name, &min_ttl_a);
        }
        if (cached_aaaa && cached_aaaa_len > 0) {
            parse_answer_and_add(&buf, cached_aaaa, (int)cached_aaaa_len, AF_INET6,
                                 pat, &prev, &addr_count, name, &min_ttl_aaaa);
        }
    } else {
        struct __res_state res;
        if (res_ninit(&res) != 0) {
            *errnop = EAGAIN;
            *h_errnop = NO_RECOVERY;
            return NSS_STATUS_UNAVAIL;
        }

        int len_a = 0, len_aaaa = 0;
        int neg_a_local = 0, neg_aaaa_local = 0;

        len_a = res_nquery(&res, name, C_IN, T_A, answer, sizeof(answer));
        if (len_a > 0) {
            parse_answer_and_add(&buf, answer, len_a, AF_INET,
                                 pat, &prev, &addr_count, name, &min_ttl_a);
        } else {
            neg_a_local = 1;
        }

        len_aaaa = res_nquery(&res, name, C_IN, T_AAAA, answer, sizeof(answer));
        if (len_aaaa > 0) {
            parse_answer_and_add(&buf, answer, len_aaaa, AF_INET6,
                                 pat, &prev, &addr_count, name, &min_ttl_aaaa);
        } else {
            neg_aaaa_local = 1;
        }

        res_nclose(&res);

        dns_cache_put(name,
                      len_a > 0 ? answer : NULL, len_a > 0 ? (size_t)len_a : 0, neg_a_local, min_ttl_a,
                      len_aaaa > 0 ? answer : NULL, len_aaaa > 0 ? (size_t)len_aaaa : 0, neg_aaaa_local, min_ttl_aaaa);
    }

    if (addr_count == 0) {
        dns_log(LOG_INFO, "No addresses found for %s", name);
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    if (addr_count > 0) {
        dns_log(LOG_DEBUG, "Final address list for %s:", name);
        print_address_list(*pat);
    }

    if (ttlp) {
        *ttlp = DEFAULT_TTL;
    }

    dns_log(LOG_INFO, "Successfully resolved %s with %d addresses", name, addr_count);
    return NSS_STATUS_SUCCESS;
}
```

- [ ] **Step 7: 修改 `_nss_hs_gethostbyname3_r` 中的日志(可选,保持委托不变)**

`_nss_hs_gethostbyname3_r` / `_nss_hs_gethostbyname2_r` / `_nss_hs_gethostbyname_r` 三个函数的委托关系不变,只是它们各自开头的 `read_cmdline` / `read_proc_path` 日志保留原样。不改动这三个函数体。

- [ ] **Step 8: 修改 constructor 和 destructor**

把文件末尾的:

```c
void __attribute__((constructor)) init(void) {
    load_custom_networks();
    dns_log(LOG_INFO, "NSS module initialized");
}

void __attribute__((destructor)) fini(void) {
    dns_log(LOG_INFO, "NSS module cleaned up");
}
```

替换为:

```c
void __attribute__((constructor)) init(void) {
    openlog("nss_hs", LOG_NDELAY | LOG_PID | LOG_CONS, LOG_LOCAL0);
    load_custom_networks();
    whitelist_initial_load();
    dns_log(LOG_INFO, "NSS module initialized");
}

void __attribute__((destructor)) fini(void) {
    whitelist_destroy();
    dns_cache_destroy();
    dns_log(LOG_INFO, "NSS module cleaned up");
    closelog();
}
```

- [ ] **Step 9: 修改 `Makefile`**

把:

```makefile
SRCS = nss_module.c dns_log.c
```

改为:

```makefile
SRCS = nss_module.c whitelist.c dns_cache.c proc_info.c dns_log.c
```

- [ ] **Step 10: 提交**

```bash
git add nss_module.c Makefile
git commit -m "$(cat <<'EOF'
Integrate whitelist + dns_cache into nss_module, refactor entry flow

- Replace #include "get_cmdchain.c" with proper headers
- Remove migrated whitelist code (now in whitelist.c)
- Add parse_answer_and_add helper (shared by cache-hit and miss paths,
  extracts min TTL via ns_rr_ttl)
- Refactor _nss_hs_gethostbyname4_r: whitelist_check_mtime + fail-open
  + dns_cache_get/put; hijack decision (is_private_ip + whitelist_match)
  still runs on cache hits, so policy changes apply to cached entries
- constructor: openlog(LOG_LOCAL0) + whitelist_initial_load
- destructor: whitelist_destroy + dns_cache_destroy + closelog
- Demote verbose address-list logging to LOG_DEBUG (gated by syslog level)
- Makefile: add whitelist.c dns_cache.c proc_info.c to SRCS

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: 更新 README

**Files:**
- Modify: `README`

- [ ] **Step 1: 重写 `README`**

```markdown
nsswitch user dns hook -- 基于 nsswitch 原理,实现对系统的 dns hook

## 处置逻辑

1. 系统发起解析域名
2. 如果返回的 IP 是内网地址(10/8、172.16/12、192.168/16、127/8、169.254/16 + 自定义段),放行
3. 如果 IP 是公网地址,对域名进行白名单比对:
   - 在白名单内 → 放行
   - 不在白名单 → 劫持本次 dns 请求,返回 127.0.0.1 / ::1
4. 白名单为空或缺失时 fail-open,放行给下游 dns 模块

## 部署方案

1. 编译安装:
   ```
   make
   sudo make install   # 安装到 /lib64/libnss_hs.so.2 + ldconfig
   ```

2. 在 `/etc/nsswitch.conf` 配置 hosts 条目,在 files 和 dns 之间新增 hs 模块:
   ```
   hosts: files hs dns
   ```

3. 配置白名单 `/etc/nss_whitelist.conf`,支持通配符逐级匹配:
   ```
   *.baidu.com        # 匹配 www.baidu.com、a.b.baidu.com,不匹配 baidu.com 本身
   baidu.com          # 精确匹配 baidu.com
   *.github.com
   github.com
   *.weibo.com
   www.sina.com
   *.aliyuncs.com
   *.aliyun.com
   ```

4. 自定义私网 IP 段 `/etc/nss_private_networks.conf`:
   ```
   100.100.0.0/16
   ```

## 热加载

修改 `/etc/nss_whitelist.conf` 后无需重启进程。模块在每次 dns 查询入口检查文件 mtime,变化时自动重载。新规则在下一次查询生效。

## 日志

日志走 syslog,facility 为 `local0`,ident 为 `nss_hs`。

### 查看日志

- journald 系统:`journalctl -t nss_hs`
- rsyslog 系统:`grep nss_hs /var/log/messages`

### 单独分文件(可选)

配置 `/etc/rsyslog.d/nss_hs.conf`:
```
local0.*    /var/log/nss_hs.log
& stop
```
然后 `sudo systemctl restart rsyslog`。

不配也能用,日志会混进 `/var/log/messages`,`grep nss_hs` 过滤即可。

### 调试日志

详细日志(地址列表逐条打印)用 `LOG_DEBUG` 级别,默认被 syslog 的 info 级别过滤丢弃。开启方法:

- rsyslog:把 `local0.*` 改成包含 debug,或单独加 `local0.debug /var/log/nss_hs.debug.log`
- journald:`journalctl -t nss_hs -p debug`

## DNS 缓存

模块内置 per-process DNS 缓存(LRU 512 条,TTL 上限 300s,负缓存 30s),减少重复上游查询。缓存只省查询,不影响策略——白名单更新对缓存条目立即生效。

## 线程安全

- 白名单:RWLock,读(查找)并发,写(重载)互斥
- 缓存:RWLock,读(查找)并发,写(插入)互斥
- 日志:syslog 内部线程安全
```

- [ ] **Step 2: 提交**

```bash
git add README
git commit -m "$(cat <<'EOF'
Update README: syslog logging, mtime hot reload, debug toggle, cache

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Linux 编译 + 集成测试

**环境:** SSH 到 `8.155.31.213`,证书 `/Users/wukong/dnshook/wukong.pem`

**前提:** Task 1-6 全部完成并提交。代码已 push 或通过 scp 传到 Linux 机器。

- [ ] **Step 1: SSH 连通性验证**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem -o StrictHostKeyChecking=no <user>@8.155.31.213 "uname -a && gcc --version"
```

Expected: 输出 Linux 内核版本和 gcc 版本。如果 `<user>` 未知,先试 `root` 或 `ec2-user` 或 `ubuntu`。

- [ ] **Step 2: 同步代码到 Linux 机器**

```bash
cd /Users/wukong/dnshook/nss_dns_hook
scp -i /Users/wukong/dnshook/wukong.pem -r . <user>@8.155.31.213:~/nss_dns_hook
```

或者如果 Linux 机器能访问 git,直接 `git clone`。

- [ ] **Step 3: 编译**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "cd ~/nss_dns_hook && make clean && make 2>&1"
```

Expected: 生成 `libnss_hs.so.2`,无 warning(`-Wall -Wextra`)。如有 warning/error,记录并修复。

- [ ] **Step 4: 安装**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "cd ~/nss_dns_hook && sudo make install && ldconfig -p | grep nss_hs"
```

Expected: `libnss_hs.so.2` 出现在 `ldconfig -p` 输出中。

- [ ] **Step 5: 配置 nsswitch**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "sudo sed -i 's/^hosts:.*/hosts: files hs dns/' /etc/nsswitch.conf && grep ^hosts: /etc/nsswitch.conf"
```

Expected: `hosts: files hs dns`

- [ ] **Step 6: 配置白名单**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "sudo cp ~/nss_dns_hook/nss_whitelist.conf /etc/nss_whitelist.conf && sudo cp ~/nss_dns_hook/nss_private_networks.conf /etc/nss_private_networks.conf && cat /etc/nss_whitelist.conf"
```

Expected: 白名单文件内容显示。

- [ ] **Step 7: 测试白名单内域名(应返回真实 IP)**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "getent hosts www.baidu.com"
```

Expected: 返回 www.baidu.com 的真实公网 IP(非 127.0.0.1)。

- [ ] **Step 8: 测试白名单外域名(应劫持到 127.0.0.1)**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "getent hosts evil.example.com"
```

Expected: 返回 `127.0.0.1`(或 NOTFOUND,取决于域名是否真的不存在,但不应返回真实公网 IP)。

- [ ] **Step 9: 测试逐级通配符匹配**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "getent hosts a.b.baidu.com"
```

Expected: 返回真实 IP(匹配 `*.baidu.com`)。如果是真实存在的百度子域名会返回 IP;即使不存在,也不应被劫持(白名单匹配放行,由上游 dns 返回 NXDOMAIN)。

- [ ] **Step 10: 测试 mtime 热加载**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "echo 'evil.example.com' | sudo tee -a /etc/nss_whitelist.conf && getent hosts evil.example.com"
```

Expected: 加入白名单后,`evil.example.com` 不再被劫持(若该域名真实存在则返回真实 IP,否则 NOTFOUND,但不再是 127.0.0.1)。

还原:
```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "sudo sed -i '/evil.example.com/d' /etc/nss_whitelist.conf"
```

- [ ] **Step 11: 测试 DNS 缓存**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "sudo tcpdump -nn -i any port 53 -c 5 -w /tmp/dns.pcap & sleep 1 && for i in 1 2 3 4 5; do getent hosts www.baidu.com; done && sleep 2 && sudo pkill tcpdump && sudo tcpdump -nn -r /tmp/dns.pcap | grep -c baidu"
```

Expected: 5 次 `getent` 但上游 DNS 查询只有 1 次(后续命中缓存)。grep 计数应为 1(或很少)。

- [ ] **Step 12: 测试多线程并发**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "for i in \$(seq 1 50); do getent hosts www.baidu.com & done; wait; echo done"
```

Expected: 50 个并发 `getent` 全部完成,无段错误,无 hang。

- [ ] **Step 13: 查看日志**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "sudo journalctl -t nss_hs --since '5 min ago' | tail -20"
```

或:
```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "grep nss_hs /var/log/messages | tail -20"
```

Expected: 看到 `ns(4) hook domain: ...` 日志,带 PID。

- [ ] **Step 14: 测试 fail-open(白名单空)**

```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "sudo mv /etc/nss_whitelist.conf /etc/nss_whitelist.conf.bak && getent hosts www.baidu.com; sudo mv /etc/nss_whitelist.conf.bak /etc/nss_whitelist.conf"
```

Expected: 白名单缺失时,`getent` 仍能返回真实 IP(fail-open 给下游 dns 模块)。

- [ ] **Step 15: 清理(可选)**

如果测试完成,可以还原 nsswitch 配置:
```bash
ssh -i /Users/wukong/dnshook/wukong.pem <user>@8.155.31.213 "sudo sed -i 's/^hosts: files hs dns/hosts: files dns/' /etc/nsswitch.conf && sudo make -C ~/nss_dns_hook uninstall"
```

- [ ] **Step 16: 记录测试结果**

把每个 step 的实际输出记录下来。如果有失败,在对应 step 标注失败原因,回到 Task 1-6 修复对应代码,重新编译测试。

---

## Self-Review

### 1. Spec coverage

| Spec 章节 | 对应 Task |
|-----------|-----------|
| §2 架构与文件结构 | Task 1-5 文件结构一致 |
| §3 whitelist 模块 | Task 3 |
| §4 dns_cache 模块 | Task 4 |
| §5 proc_info 模块 | Task 1 |
| §6 dns_log 模块 | Task 2 |
| §7 nss_module.c 集成 | Task 5 |
| §8 Makefile | Task 5 Step 9 |
| §9 错误处理与线程安全 | Task 3/4/5(RWLock + fail-open + 错误路径) |
| §10 测试策略 | Task 7 |
| §11 部署配套 | Task 6 README + Task 7 部署步骤 |

无遗漏。

### 2. Placeholder scan

无 TBD / TODO / "implement later"。所有代码步骤都有完整代码。Task 7 的 `<user>` 是占位符(Linux 用户名未知),在 Step 1 确认。

### 3. Type consistency

- `whitelist_match(const char *domain) -> int`:Task 3 定义,Task 5 `add_ipv4_address` / `add_ipv6_address` 内部调用 — 一致(原代码已调用 `is_domain_whitelisted`,现改为 `whitelist_match`,签名相同)
- `dns_cache_get` / `dns_cache_put` 签名:Task 4 定义,Task 5 Step 6 调用 — 参数顺序和类型一致
- `parse_answer_and_add` 签名:Task 5 Step 5 定义,Step 6 调用 — 一致
- `proc_stat` / `cmd_chain_struct`:Task 1 定义,与原 `get_cmdchain.c` 一致(typedef 名不变)
- `LOG_DEBUG`:Task 2 定义,Task 5 Step 4 使用 — 一致
