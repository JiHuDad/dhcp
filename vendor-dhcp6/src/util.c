#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <libgen.h>
#include "util.h"
#include "log.h"

int read_file_all(const char *path, uint8_t **buf, size_t *len) {
    if (!path || !buf || !len) return -1;
    
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        log_error("Failed to open file %s: %s", path, strerror(errno));
        return -1;
    }
    
    // Get file size
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        log_error("Failed to seek to end of file %s", path);
        return -1;
    }
    
    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        log_error("Failed to get file size for %s", path);
        return -1;
    }
    
    rewind(fp);
    
    // Allocate buffer
    uint8_t *buffer = malloc(file_size + 1); // +1 for null terminator
    if (!buffer) {
        fclose(fp);
        log_error("Failed to allocate memory for file %s", path);
        return -1;
    }
    
    // Read file
    size_t bytes_read = fread(buffer, 1, file_size, fp);
    fclose(fp);
    
    if (bytes_read != (size_t)file_size) {
        free(buffer);
        log_error("Failed to read complete file %s", path);
        return -1;
    }
    
    buffer[file_size] = '\0'; // Null terminate for safety
    
    *buf = buffer;
    *len = file_size;
    
    log_debug("Successfully read %zu bytes from %s", *len, path);
    return 0;
}

int write_file(const char *path, const uint8_t *data, size_t len, mode_t mode) {
    if (!path || !data) return -1;
    
    // Ensure directory exists
    char *dir_path = strdup(path);
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        if (ensure_directory(dir_path, 0750) != 0) {
            free(dir_path);
            return -1;
        }
    }
    free(dir_path);
    
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        log_error("Failed to open file %s for writing: %s", path, strerror(errno));
        return -1;
    }
    
    size_t bytes_written = fwrite(data, 1, len, fp);
    fclose(fp);
    
    if (bytes_written != len) {
        log_error("Failed to write complete data to %s", path);
        return -1;
    }
    
    // Set file permissions
    if (chmod(path, mode) != 0) {
        log_warn("Failed to set permissions on %s: %s", path, strerror(errno));
        // Don't fail for permission errors
    }
    
    log_debug("Successfully wrote %zu bytes to %s", len, path);
    return 0;
}

void trim_spaces_inplace(char *str) {
    if (!str) return;
    
    // Trim leading spaces
    char *start = str;
    while (*start && isspace(*start)) {
        start++;
    }
    
    // Move string to beginning if we trimmed leading spaces
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
    
    // Trim trailing spaces
    char *end = str + strlen(str) - 1;
    while (end >= str && isspace(*end)) {
        *end = '\0';
        end--;
    }
}

int ensure_directory(const char *path, mode_t mode) {
    if (!path) return -1;
    
    struct stat st;
    
    // Check if directory already exists
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0; // Directory exists
        } else {
            log_error("Path %s exists but is not a directory", path);
            return -1;
        }
    }
    
    // Create directory (and parent directories if needed)
    char *path_copy = strdup(path);
    char *p = path_copy;
    
    // Skip leading slash
    if (*p == '/') p++;
    
    while (*p) {
        char *slash = strchr(p, '/');
        if (slash) {
            *slash = '\0';
        }
        
        if (stat(path_copy, &st) != 0) {
            if (mkdir(path_copy, mode) != 0) {
                log_error("Failed to create directory %s: %s", path_copy, strerror(errno));
                free(path_copy);
                return -1;
            }
        }
        
        if (slash) {
            *slash = '/';
            p = slash + 1;
        } else {
            break;
        }
    }
    
    free(path_copy);
    
    log_debug("Successfully ensured directory %s exists", path);
    return 0;
}

int check_file_permissions(const char *path, mode_t expected) {
    if (!path) return -1;
    
    struct stat st;
    if (stat(path, &st) != 0) {
        log_error("Failed to stat file %s: %s", path, strerror(errno));
        return -1;
    }
    
    mode_t actual = st.st_mode & 0777;
    if (actual != expected) {
        log_warn("File %s has permissions %o, expected %o", path, actual, expected);
        return -1;
    }
    
    return 0;
}

char *get_env_trimmed(const char *name) {
    if (!name) return NULL;
    
    const char *value = getenv(name);
    if (!value) {
        log_debug("Environment variable %s not set", name);
        return NULL;
    }
    
    char *trimmed = strdup(value);
    if (trimmed) {
        trim_spaces_inplace(trimmed);
        
        // Log only first 8 characters for security
        if (strlen(trimmed) > 8) {
            log_debug("Environment variable %s = %.8s... (%zu chars)", 
                     name, trimmed, strlen(trimmed));
        } else {
            log_debug("Environment variable %s = %s", name, trimmed);
        }
    }
    
    return trimmed;
}