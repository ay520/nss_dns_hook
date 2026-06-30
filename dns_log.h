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
