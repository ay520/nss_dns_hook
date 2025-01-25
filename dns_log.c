#include "dns_log.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>

// 默认日志文件
static char LOG_FILE[MAX_PATH_LENGTH] = "/var/log/dns_security.log";

void set_log_file(const char *filepath) {
    if (filepath) {
        strncpy(LOG_FILE, filepath, MAX_PATH_LENGTH - 1);
        LOG_FILE[MAX_PATH_LENGTH - 1] = '\0'; // 确保字符串结尾
    }
}

void dns_log(int log_level, const char *format, ...) {
    char log_dir[MAX_PATH_LENGTH];
    strncpy(log_dir, LOG_FILE, MAX_PATH_LENGTH - 1);
    log_dir[MAX_PATH_LENGTH - 1] = '\0';

    char *last_slash = strrchr(log_dir, '/'); 

    if (last_slash) {
        *last_slash = '\0';
        if (access(log_dir, F_OK) == -1) {
            mkdir(log_dir, 0755); // 改为 755 确保目录也可执行搜索
        }
        *last_slash = '/';
    }

    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now;
        time(&now);
        struct tm *tm_info = localtime(&now);
        
        char time_buf[20];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
        
        const char *level_str;
        switch (log_level) {
            case LOG_INFO:    level_str = "INFO"; break;
            case LOG_WARNING: level_str = "WARNING"; break;
            case LOG_ERROR:   level_str = "ERROR"; break;
            default:          level_str = "UNKNOWN"; break;
        }

        fprintf(log_file, "[%s] [%s]: ", time_buf, level_str);

        va_list args;
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        
        fprintf(log_file, "\n");
        fclose(log_file);
    }
}
