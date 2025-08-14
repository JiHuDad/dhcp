#ifndef LOG_H
#define LOG_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    LOG_ERROR = 0,
    LOG_WARN  = 1,
    LOG_INFO  = 2,
    LOG_DEBUG = 3
} log_level_t;

int log_init(const char *path, const char *level_str, int hex_dump);
void log_cleanup(void);

void log_error(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_debug(const char *fmt, ...);

void log_hex_dump(const char *prefix, const uint8_t *data, size_t len);

#endif // LOG_H