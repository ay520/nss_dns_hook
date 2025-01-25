#ifndef DNS_LOG_H
#define DNS_LOG_H

#define MAX_PATH_LENGTH 512

// 日志类型定义
#define LOG_INFO    6
#define LOG_WARNING 4
#define LOG_ERROR   3

#ifdef __cplusplus
extern "C" {
#endif

// 设置日志文件路径
void set_log_file(const char *filepath);

// 日志写入函数，支持日志级别和格式化字符串
void dns_log(int log_level, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* DNS_LOG_H */
