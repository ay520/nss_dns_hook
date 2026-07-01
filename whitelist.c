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
    whitelist_free_hash(whitelist_hash);
    whitelist_hash = new_hash;
    whitelist_count = count;
    whitelist_mtime = mtime;
    pthread_rwlock_unlock(&whitelist_lock);
}

void whitelist_check_mtime(void) {
    struct stat st;
    if (stat(WHITELIST_FILE, &st) != 0) return;
    if (st.st_mtime == whitelist_mtime) return;

    // Build new hash outside lock (expensive: file I/O + parse)
    int count;
    time_t mtime;
    struct whitelist_entry *new_hash = whitelist_build_hash(&count, &mtime);

    pthread_rwlock_wrlock(&whitelist_lock);
    // Double-check: another thread may have reloaded already
    if (mtime != whitelist_mtime) {
        struct whitelist_entry *old = whitelist_hash;
        whitelist_hash = new_hash;
        whitelist_count = count;
        whitelist_mtime = mtime;
        new_hash = NULL;  // consumed by swap
        whitelist_free_hash(old);
    }
    pthread_rwlock_unlock(&whitelist_lock);

    // If we didn't swap (another thread won the race), free unused new_hash
    if (new_hash) {
        whitelist_free_hash(new_hash);
    }
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
