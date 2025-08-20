#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <strings.h>
#include "log.h"

static FILE *log_file = NULL;
static log_level_t current_level = LOG_INFO;
static int hex_dump_enabled = 0;

static const char *level_names[] = {
    "ERROR", "WARN", "INFO", "DEBUG"
};

static const char *level_colors[] = {
    "\033[31m", // red
    "\033[33m", // yellow  
    "\033[32m", // green
    "\033[36m"  // cyan
};

static log_level_t parse_log_level(const char *level_str) {
    if (!level_str) return LOG_INFO;
    
    if (strcasecmp(level_str, "error") == 0) return LOG_ERROR;
    if (strcasecmp(level_str, "warn") == 0) return LOG_WARN;
    if (strcasecmp(level_str, "info") == 0) return LOG_INFO;
    if (strcasecmp(level_str, "debug") == 0) return LOG_DEBUG;
    
    return LOG_INFO;
}

static void write_log(log_level_t level, const char *fmt, va_list args) {
    if (level > current_level) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Color output for console if stdout is a tty
    int use_color = isatty(STDOUT_FILENO);
    
    // Write to console
    if (use_color) {
        printf("%s[%s] %s%s: ", level_colors[level], timestamp, level_names[level], "\033[0m");
    } else {
        printf("[%s] %s: ", timestamp, level_names[level]);
    }
    vprintf(fmt, args);
    printf("\n");
    fflush(stdout);
    
    // Write to file if configured
    if (log_file) {
        fprintf(log_file, "[%s] %s: ", timestamp, level_names[level]);
        vfprintf(log_file, fmt, args);
        fprintf(log_file, "\n");
        fflush(log_file);
    }
}

int log_init(const char *path, const char *level_str, int hex_dump) {
    current_level = parse_log_level(level_str);
    hex_dump_enabled = hex_dump;
    
    if (path && strlen(path) > 0) {
        // Ensure directory exists
        char *dir_path = strdup(path);
        char *last_slash = strrchr(dir_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            struct stat st;
            if (stat(dir_path, &st) != 0) {
                if (mkdir(dir_path, 0755) != 0) {
                    fprintf(stderr, "Failed to create log directory %s: %s\n", 
                            dir_path, strerror(errno));
                    free(dir_path);
                    return -1;
                }
            }
        }
        free(dir_path);
        
        log_file = fopen(path, "a");
        if (!log_file) {
            fprintf(stderr, "Failed to open log file %s: %s\n", path, strerror(errno));
            return -1;
        }
        
        // Set file permissions to 0640
        if (chmod(path, 0640) != 0) {
            fprintf(stderr, "Warning: Failed to set log file permissions: %s\n", strerror(errno));
        }
    }
    
    return 0;
}

void log_cleanup(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_log(LOG_ERROR, fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_log(LOG_WARN, fmt, args);
    va_end(args);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_log(LOG_INFO, fmt, args);
    va_end(args);
}

void log_debug(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_log(LOG_DEBUG, fmt, args);
    va_end(args);
}

void log_hex_dump(const char *prefix, const uint8_t *data, size_t len) {
    if (!hex_dump_enabled || current_level < LOG_DEBUG) return;
    
    char hex_line[80];
    char ascii_line[20];
    size_t line_pos = 0;
    
    log_debug("%s (length: %zu bytes):", prefix, len);
    
    for (size_t i = 0; i < len; i++) {
        if (line_pos == 0) {
            snprintf(hex_line, sizeof(hex_line), "%04zx: ", i);
        }
        
        snprintf(hex_line + strlen(hex_line), sizeof(hex_line) - strlen(hex_line), 
                 "%02x ", data[i]);
        
        // ASCII representation
        ascii_line[line_pos] = (data[i] >= 32 && data[i] <= 126) ? data[i] : '.';
        line_pos++;
        
        if (line_pos == 16 || i == len - 1) {
            // Pad hex line if needed
            while (line_pos < 16) {
                strncat(hex_line, "   ", sizeof(hex_line) - strlen(hex_line) - 1);
                line_pos++;
            }
            
            ascii_line[i % 16 + 1] = '\0';
            log_debug("%s |%s|", hex_line, ascii_line);
            line_pos = 0;
            memset(ascii_line, 0, sizeof(ascii_line));
        }
    }
}