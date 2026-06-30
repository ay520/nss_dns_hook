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
