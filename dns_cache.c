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
