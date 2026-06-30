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
