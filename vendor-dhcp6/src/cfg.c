#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <strings.h>
#include "cfg.h"
#include "log.h"

// Simple TOML-like parser for our specific config format
static char *trim_whitespace(char *str) {
    char *end;
    
    // Trim leading space
    while (*str == ' ' || *str == '\t') str++;
    
    if (*str == 0) return str;
    
    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) end--;
    
    end[1] = '\0';
    return str;
}

static char *parse_string_value(const char *line) {
    const char *start = strchr(line, '=');
    if (!start) return NULL;
    
    start = trim_whitespace((char*)start + 1);
    
    // Remove quotes if present
    if (*start == '"') {
        start++;
        char *end = strrchr(start, '"');
        if (end) *end = '\0';
    }
    
    return strdup(start);
}

static int parse_int_value(const char *line) {
    const char *start = strchr(line, '=');
    if (!start) return -1;
    
    return atoi(trim_whitespace((char*)start + 1));
}

static bool parse_bool_value(const char *line) {
    const char *start = strchr(line, '=');
    if (!start) return false;
    
    start = trim_whitespace((char*)start + 1);
    return (strcmp(start, "true") == 0);
}

int cfg_load(const char *path, app_cfg_t *cfg) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        log_error("Failed to open config file %s: %s", path, strerror(errno));
        return -1;
    }
    
    // Initialize with defaults
    memset(cfg, 0, sizeof(*cfg));
    
    // Set defaults
    cfg->dhcp6.iface = strdup("eth0");
    cfg->dhcp6.duid_path = strdup("/var/lib/vendor-dhcp6/duid");
    cfg->dhcp6.timeout_seconds = 30;
    
    cfg->vendor.enterprise = 99999;
    cfg->vendor.sn_env = strdup("SN_NUMBER");
    cfg->vendor.code_sn = 71;
    cfg->vendor.code_sig = 72;
    cfg->vendor.code_cert_req = 73;
    cfg->vendor.code_sig_dup = 74;
    cfg->vendor.code_cert_reply = 77;
    
    cfg->paths.private_key = strdup("/etc/vendor/keys/client.key");
    cfg->paths.request_cert = strdup("/etc/vendor/certs/request.pem");
    cfg->paths.reply_cert0 = strdup("/var/lib/vendor-dhcp6/server0.pem");
    cfg->paths.reply_cert1 = strdup("/var/lib/vendor-dhcp6/server1.pem");
    cfg->paths.reply_chain_bundle = strdup("/var/lib/vendor-dhcp6/server_chain.pem");
    
    cfg->advertise_gate.enabled = true;
    cfg->advertise_gate.require_vendor = true;
    cfg->advertise_gate.require_vendor_subopt = 90;
    
    cfg->logging.path = strdup("/var/log/vendor-dhcp6.log");
    cfg->logging.level = strdup("info");
    cfg->logging.hex_dump = false;
    
    char line[1024];
    char current_section[64] = "";
    
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim_whitespace(line);
        
        // Skip empty lines and comments
        if (*trimmed == '\0' || *trimmed == '#') continue;
        
        // Section headers
        if (*trimmed == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                strcpy(current_section, trimmed + 1);
            }
            continue;
        }
        
        // Key-value pairs
        if (strcmp(current_section, "dhcp6") == 0) {
            if (strncmp(trimmed, "iface", 5) == 0) {
                free(cfg->dhcp6.iface);
                cfg->dhcp6.iface = parse_string_value(trimmed);
            } else if (strncmp(trimmed, "duid_path", 9) == 0) {
                free(cfg->dhcp6.duid_path);
                cfg->dhcp6.duid_path = parse_string_value(trimmed);
            } else if (strncmp(trimmed, "timeout_seconds", 15) == 0) {
                cfg->dhcp6.timeout_seconds = parse_int_value(trimmed);
            }
        } else if (strcmp(current_section, "vendor") == 0) {
            if (strncmp(trimmed, "enterprise", 10) == 0) {
                cfg->vendor.enterprise = (uint32_t)parse_int_value(trimmed);
            } else if (strncmp(trimmed, "sn_env", 6) == 0) {
                free(cfg->vendor.sn_env);
                cfg->vendor.sn_env = parse_string_value(trimmed);
            } else if (strncmp(trimmed, "code_sn", 7) == 0) {
                cfg->vendor.code_sn = (uint16_t)parse_int_value(trimmed);
            } else if (strncmp(trimmed, "code_sig", 8) == 0) {
                cfg->vendor.code_sig = (uint16_t)parse_int_value(trimmed);
            } else if (strncmp(trimmed, "code_cert_req", 13) == 0) {
                cfg->vendor.code_cert_req = (uint16_t)parse_int_value(trimmed);
            } else if (strncmp(trimmed, "code_sig_dup", 12) == 0) {
                cfg->vendor.code_sig_dup = (uint16_t)parse_int_value(trimmed);
            } else if (strncmp(trimmed, "code_cert_reply", 15) == 0) {
                cfg->vendor.code_cert_reply = (uint16_t)parse_int_value(trimmed);
            }
        } else if (strcmp(current_section, "paths") == 0) {
            if (strncmp(trimmed, "private_key", 11) == 0) {
                free(cfg->paths.private_key);
                cfg->paths.private_key = parse_string_value(trimmed);
            } else if (strncmp(trimmed, "request_cert", 12) == 0) {
                free(cfg->paths.request_cert);
                cfg->paths.request_cert = parse_string_value(trimmed);
            } else if (strncmp(trimmed, "reply_cert0", 11) == 0) {
                free(cfg->paths.reply_cert0);
                cfg->paths.reply_cert0 = parse_string_value(trimmed);
            } else if (strncmp(trimmed, "reply_cert1", 11) == 0) {
                free(cfg->paths.reply_cert1);
                cfg->paths.reply_cert1 = parse_string_value(trimmed);
            } else if (strncmp(trimmed, "reply_chain_bundle", 18) == 0) {
                free(cfg->paths.reply_chain_bundle);
                cfg->paths.reply_chain_bundle = parse_string_value(trimmed);
            }
        } else if (strcmp(current_section, "advertise_gate") == 0) {
            if (strncmp(trimmed, "enabled", 7) == 0) {
                cfg->advertise_gate.enabled = parse_bool_value(trimmed);
            } else if (strncmp(trimmed, "require_vendor", 14) == 0) {
                cfg->advertise_gate.require_vendor = parse_bool_value(trimmed);
            } else if (strncmp(trimmed, "require_vendor_subopt", 21) == 0) {
                cfg->advertise_gate.require_vendor_subopt = parse_int_value(trimmed);
            }
        } else if (strcmp(current_section, "logging") == 0) {
            if (strncmp(trimmed, "level", 5) == 0) {
                free(cfg->logging.level);
                cfg->logging.level = parse_string_value(trimmed);
            } else if (strncmp(trimmed, "path", 4) == 0) {
                free(cfg->logging.path);
                cfg->logging.path = parse_string_value(trimmed);
            } else if (strncmp(trimmed, "hex_dump", 8) == 0) {
                cfg->logging.hex_dump = parse_bool_value(trimmed);
            }
        }
    }
    
    fclose(fp);
    return 0;
}

void cfg_free(app_cfg_t *cfg) {
    if (!cfg) return;
    
    free(cfg->dhcp6.iface);
    free(cfg->dhcp6.duid_path);
    
    free(cfg->vendor.sn_env);
    
    free(cfg->paths.private_key);
    free(cfg->paths.request_cert);
    free(cfg->paths.reply_cert0);
    free(cfg->paths.reply_cert1);
    free(cfg->paths.reply_chain_bundle);
    
    free(cfg->logging.path);
    free(cfg->logging.level);
    
    memset(cfg, 0, sizeof(*cfg));
}

int cfg_validate(const app_cfg_t *cfg) {
    if (!cfg) return -1;
    
    // Check required fields
    if (!cfg->dhcp6.iface || !cfg->vendor.sn_env) {
        log_error("Missing required configuration fields");
        return -1;
    }
    
    // Check enterprise number
    if (cfg->vendor.enterprise == 0) {
        log_error("Invalid enterprise number: %u", cfg->vendor.enterprise);
        return -1;
    }
    
    // Check file paths exist and have proper permissions
    struct stat st;
    if (stat(cfg->paths.private_key, &st) != 0) {
        log_error("Private key file not found: %s", cfg->paths.private_key);
        return -1;
    }
    
    if (stat(cfg->paths.request_cert, &st) != 0) {
        log_error("Request certificate file not found: %s", cfg->paths.request_cert);
        return -1;
    }
    
    // Check log level
    if (strcmp(cfg->logging.level, "debug") != 0 &&
        strcmp(cfg->logging.level, "info") != 0 &&
        strcmp(cfg->logging.level, "warn") != 0 &&
        strcmp(cfg->logging.level, "error") != 0) {
        log_error("Invalid log level: %s", cfg->logging.level);
        return -1;
    }
    
    return 0;
}