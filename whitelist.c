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
