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
