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

// Free all entries in an arbitrary hash (caller manages the head pointer)
static void whitelist_free_hash(struct whitelist_entry *hash) {
    if (!hash) return;
    struct whitelist_entry *cur, *tmp;
    HASH_ITER(hh, hash, cur, tmp) {
        HASH_DEL(hash, cur);
        free(cur->domain);
        free(cur);
    }
}

// Read whitelist file and build a new hash. Returns new_hash (NULL if file
// missing/empty). Sets *out_count and *out_mtime. Does NOT touch global state
// — caller swaps under lock.
static struct whitelist_entry *whitelist_build_hash(int *out_count, time_t *out_mtime) {
    *out_count = 0;
    *out_mtime = 0;

    FILE *fp = fopen(WHITELIST_FILE, "r");
    if (!fp) {
        dns_log(LOG_WARNING, "Could not open whitelist file: %s", WHITELIST_FILE);
        return NULL;
    }

    struct stat st;
    if (stat(WHITELIST_FILE, &st) == 0) {
        *out_mtime = st.st_mtime;
    } else if (fstat(fileno(fp), &st) == 0) {
        // stat 失败但 fopen 成功(文件可能被替换),回退到 fstat
        *out_mtime = st.st_mtime;
    } else {
        // 都失败,用当前时间作非零哨兵,保证下次 check_mtime 能检测到变化
        *out_mtime = time(NULL);
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

    *out_count = count;
    dns_log(LOG_INFO, "Loaded %d domains into whitelist", count);
    return new_hash;
}

void whitelist_initial_load(void) {
    int count;
    time_t mtime;
    struct whitelist_entry *new_hash = whitelist_build_hash(&count, &mtime);

    pthread_rwlock_wrlock(&whitelist_lock);
    struct whitelist_entry *old = whitelist_hash;
    whitelist_hash = new_hash;
    whitelist_count = count;
    whitelist_mtime = mtime;
    pthread_rwlock_unlock(&whitelist_lock);

    // old hash 在锁外释放,避免阻塞并发读者
    if (old) whitelist_free_hash(old);
}

void whitelist_check_mtime(void) {
    struct stat st;
    if (stat(WHITELIST_FILE, &st) != 0) return;
    // 记录决策时的 mtime,用于 wrlock 下的 double-check
    time_t old_mtime = whitelist_mtime;
    if (st.st_mtime == old_mtime) return;

    // 在锁外构建新 hash(耗时:文件 I/O + 解析)
    int count;
    time_t mtime;
    struct whitelist_entry *new_hash = whitelist_build_hash(&count, &mtime);

    struct whitelist_entry *old_to_free = NULL;
    pthread_rwlock_wrlock(&whitelist_lock);
    // double-check:若全局 mtime 仍是 old_mtime,说明没有其他线程重载过,执行 swap
    // 若全局 mtime 已变(其他线程重载了更新版本),跳过 swap,丢弃本次 new_hash
    if (whitelist_mtime == old_mtime) {
        old_to_free = whitelist_hash;
        whitelist_hash = new_hash;
        whitelist_count = count;
        whitelist_mtime = mtime;
        new_hash = NULL;  // 已 swap,标记不需要在外面释放
    }
    pthread_rwlock_unlock(&whitelist_lock);

    // 锁外释放:丢弃的 new_hash(竞态输掉)或被替换的 old hash
    if (new_hash) whitelist_free_hash(new_hash);
    if (old_to_free) whitelist_free_hash(old_to_free);
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
    whitelist_free_hash(whitelist_hash);
    whitelist_hash = NULL;
    whitelist_count = 0;
    whitelist_mtime = 0;
    pthread_rwlock_unlock(&whitelist_lock);
}
