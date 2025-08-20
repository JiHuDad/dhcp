#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

int read_file_all(const char *path, uint8_t **buf, size_t *len);
int write_file(const char *path, const uint8_t *data, size_t len, mode_t mode);

void trim_spaces_inplace(char *str);
int ensure_directory(const char *path, mode_t mode);
int check_file_permissions(const char *path, mode_t expected);

char *get_env_trimmed(const char *name);

#endif // UTIL_H