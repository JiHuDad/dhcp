#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include "dhcp6_vendor.h"
#include "crypto.h"
#include "util.h"
#include "log.h"

// DHCPv6 message types
#define DHCPV6_SOLICIT     1
#define DHCPV6_ADVERTISE   2
#define DHCPV6_REQUEST     3
#define DHCPV6_REPLY       7

// Basic DHCPv6 header
typedef struct {
    uint8_t msg_type;
    uint8_t transaction_id[3];
} __attribute__((packed)) dhcpv6_header_t;

// DHCPv6 option header
typedef struct {
    uint16_t code;
    uint16_t length;
} __attribute__((packed)) dhcpv6_option_t;

int vso_append_subopt(uint8_t *buf, size_t cap, size_t *pos,
                      uint16_t code, const uint8_t *value, uint16_t value_len) {
    if (!buf || !pos) return -1;
    
    size_t needed = 4 + value_len; // 2 bytes code + 2 bytes length + value
    if (*pos + needed > cap) {
        log_error("VSO buffer too small: need %zu, have %zu", *pos + needed, cap);
        return -ENOSPC;
    }
    
    // Write sub-option code (network byte order)
    uint16_t net_code = htons(code);
    memcpy(buf + *pos, &net_code, 2);
    *pos += 2;
    
    // Write sub-option length (network byte order)
    uint16_t net_length = htons(value_len);
    memcpy(buf + *pos, &net_length, 2);
    *pos += 2;
    
    // Write value
    if (value_len > 0 && value) {
        memcpy(buf + *pos, value, value_len);
        *pos += value_len;
    }
    
    log_debug("Added VSO sub-option: code=%u, length=%u", code, value_len);
    return 0;
}

int build_request_vso(const app_cfg_t *cfg, uint8_t *out, size_t cap, size_t *used) {
    if (!cfg || !out || !used) return -1;
    
    size_t pos = 0;
    
    // VSO starts with enterprise number (4 bytes, network byte order)
    if (pos + 4 > cap) return -ENOSPC;
    
    uint32_t enterprise = htonl(cfg->vendor.enterprise);
    memcpy(out + pos, &enterprise, 4);
    pos += 4;
    
    // Get SN_NUMBER from environment
    char *sn_number = get_env_trimmed(cfg->vendor.sn_env);
    if (!sn_number) {
        log_error("Environment variable %s not set", cfg->vendor.sn_env);
        return -1;
    }
    
    log_info("Using SN_NUMBER: %.8s... (%zu chars)", sn_number, strlen(sn_number));
    
    // Sub-option 71: SN_NUMBER
    if (vso_append_subopt(out, cap, &pos, cfg->vendor.code_sn,
                         (uint8_t*)sn_number, strlen(sn_number)) != 0) {
        free(sn_number);
        return -1;
    }
    
    // Sub-option 72: RSA signature of SN_NUMBER (Base64)
    privkey_t *private_key = NULL;
    if (crypto_load_private_key(cfg->paths.private_key, NULL, &private_key) != 0) {
        free(sn_number);
        return -1;
    }
    
    uint8_t signature[512]; // RSA-2048 signature is 256 bytes, but allow some margin
    size_t sig_len = sizeof(signature);
    
    if (crypto_rsa_sign_sha256(private_key, (uint8_t*)sn_number, strlen(sn_number),
                              signature, &sig_len) != 0) {
        log_error("Failed to create RSA signature");
        crypto_free_private_key(private_key);
        free(sn_number);
        return -1;
    }
    
    crypto_free_private_key(private_key);
    
    char *sig_base64 = base64_encode(signature, sig_len);
    if (!sig_base64) {
        log_error("Failed to encode signature as Base64");
        free(sn_number);
        return -1;
    }
    
    log_info("Created RSA signature: %.8s... (%zu chars)", sig_base64, strlen(sig_base64));
    
    if (vso_append_subopt(out, cap, &pos, cfg->vendor.code_sig,
                         (uint8_t*)sig_base64, strlen(sig_base64)) != 0) {
        free(sig_base64);
        free(sn_number);
        return -1;
    }
    
    // Sub-option 73: Request certificate
    uint8_t *cert_data;
    size_t cert_len;
    if (read_file_all(cfg->paths.request_cert, &cert_data, &cert_len) != 0) {
        free(sig_base64);
        free(sn_number);
        return -1;
    }
    
    if (vso_append_subopt(out, cap, &pos, cfg->vendor.code_cert_req,
                         cert_data, cert_len) != 0) {
        free(cert_data);
        free(sig_base64);
        free(sn_number);
        return -1;
    }
    
    free(cert_data);
    log_info("Added request certificate (%zu bytes)", cert_len);
    
    // Sub-option 74: Duplicate signature (same as 72)
    if (vso_append_subopt(out, cap, &pos, cfg->vendor.code_sig_dup,
                         (uint8_t*)sig_base64, strlen(sig_base64)) != 0) {
        free(sig_base64);
        free(sn_number);
        return -1;
    }
    
    // Clear sensitive data
    memset(signature, 0, sizeof(signature));
    free(sig_base64);
    free(sn_number);
    
    *used = pos;
    
    log_info("Built VSO for Request: enterprise=%u, %zu bytes total",
             cfg->vendor.enterprise, *used);
    
    log_hex_dump("VSO payload", out, *used);
    
    return 0;
}

const uint8_t *find_dhcp6_option(const uint8_t *pkt, size_t len,
                                 uint16_t option_code, uint16_t *option_len) {
    if (!pkt || len < sizeof(dhcpv6_header_t)) return NULL;
    
    const uint8_t *pos = pkt + sizeof(dhcpv6_header_t);
    const uint8_t *end = pkt + len;
    
    while (pos + sizeof(dhcpv6_option_t) <= end) {
        dhcpv6_option_t *opt = (dhcpv6_option_t*)pos;
        uint16_t code = ntohs(opt->code);
        uint16_t opt_len = ntohs(opt->length);
        
        if (pos + sizeof(dhcpv6_option_t) + opt_len > end) {
            log_warn("Truncated DHCPv6 option %u", code);
            break;
        }
        
        if (code == option_code) {
            if (option_len) *option_len = opt_len;
            return pos + sizeof(dhcpv6_option_t);
        }
        
        pos += sizeof(dhcpv6_option_t) + opt_len;
    }
    
    return NULL;
}

const uint8_t *find_vso_subopt(const uint8_t *vso_data, size_t vso_len,
                               uint32_t enterprise, uint16_t subopt_code,
                               uint16_t *subopt_len) {
    if (!vso_data || vso_len < 4) return NULL;
    
    // Check enterprise number
    uint32_t pkt_enterprise = ntohl(*(uint32_t*)vso_data);
    if (pkt_enterprise != enterprise) {
        log_debug("VSO enterprise mismatch: got %u, expected %u", pkt_enterprise, enterprise);
        return NULL;
    }
    
    const uint8_t *pos = vso_data + 4;
    const uint8_t *end = vso_data + vso_len;
    
    while (pos + 4 <= end) {
        uint16_t code = ntohs(*(uint16_t*)pos);
        uint16_t length = ntohs(*(uint16_t*)(pos + 2));
        
        if (pos + 4 + length > end) {
            log_warn("Truncated VSO sub-option %u", code);
            break;
        }
        
        if (code == subopt_code) {
            if (subopt_len) *subopt_len = length;
            return pos + 4;
        }
        
        pos += 4 + length;
    }
    
    return NULL;
}

bool check_advertise_gate(const app_cfg_t *cfg, const uint8_t *pkt, size_t len) {
    if (!cfg || !cfg->advertise_gate.enabled) {
        log_debug("Advertise gate disabled, allowing");
        return true;
    }
    
    if (!pkt || len < sizeof(dhcpv6_header_t)) {
        log_warn("Invalid DHCPv6 packet");
        return false;
    }
    
    dhcpv6_header_t *hdr = (dhcpv6_header_t*)pkt;
    if (hdr->msg_type != DHCPV6_ADVERTISE) {
        log_warn("Not an Advertise message: type=%u", hdr->msg_type);
        return false;
    }
    
    if (!cfg->advertise_gate.require_vendor) {
        log_debug("Vendor requirement disabled, allowing");
        return true;
    }
    
    // Look for VSO with our enterprise number
    uint16_t vso_len;
    const uint8_t *vso_data = find_dhcp6_option(pkt, len, DHCPv6_OPTION_VENDOR_OPTS, &vso_len);
    if (!vso_data) {
        log_info("Advertise gate: No VSO found");
        return false;
    }
    
    // Check if required sub-option exists
    if (cfg->advertise_gate.require_vendor_subopt >= 0) {
        uint16_t subopt_len;
        const uint8_t *subopt_data = find_vso_subopt(vso_data, vso_len,
                                                     cfg->vendor.enterprise,
                                                     cfg->advertise_gate.require_vendor_subopt,
                                                     &subopt_len);
        if (!subopt_data) {
            log_info("Advertise gate: Required sub-option %u not found",
                     cfg->advertise_gate.require_vendor_subopt);
            return false;
        }
        
        log_info("Advertise gate: Found required sub-option %u (%u bytes)",
                 cfg->advertise_gate.require_vendor_subopt, subopt_len);
    }
    
    log_info("Advertise gate: Passed all checks");
    return true;
}

bool is_valid_pem_cert(const char *pem_str) {
    if (!pem_str) return false;
    
    const char *begin_marker = "-----BEGIN CERTIFICATE-----";
    const char *end_marker = "-----END CERTIFICATE-----";
    
    const char *begin = strstr(pem_str, begin_marker);
    const char *end = strstr(pem_str, end_marker);
    
    return (begin != NULL && end != NULL && end > begin);
}

int split_pem_chain(const char *chain_str, char **cert1, char **cert2) {
    if (!chain_str || !cert1 || !cert2) return -1;
    
    *cert1 = NULL;
    *cert2 = NULL;
    
    // Find first certificate
    const char *begin1 = strstr(chain_str, "-----BEGIN CERTIFICATE-----");
    if (!begin1) {
        log_error("No certificate found in chain");
        return -1;
    }
    
    const char *end1 = strstr(begin1, "-----END CERTIFICATE-----");
    if (!end1) {
        log_error("Incomplete first certificate");
        return -1;
    }
    end1 += strlen("-----END CERTIFICATE-----");
    
    // Find second certificate
    const char *begin2 = strstr(end1, "-----BEGIN CERTIFICATE-----");
    if (!begin2) {
        log_error("Second certificate not found");
        return -1;
    }
    
    const char *end2 = strstr(begin2, "-----END CERTIFICATE-----");
    if (!end2) {
        log_error("Incomplete second certificate");
        return -1;
    }
    end2 += strlen("-----END CERTIFICATE-----");
    
    // Extract certificates
    size_t cert1_len = end1 - begin1;
    size_t cert2_len = end2 - begin2;
    
    *cert1 = malloc(cert1_len + 1);
    *cert2 = malloc(cert2_len + 1);
    
    if (!*cert1 || !*cert2) {
        free(*cert1);
        free(*cert2);
        *cert1 = *cert2 = NULL;
        return -1;
    }
    
    memcpy(*cert1, begin1, cert1_len);
    (*cert1)[cert1_len] = '\0';
    
    memcpy(*cert2, begin2, cert2_len);
    (*cert2)[cert2_len] = '\0';
    
    log_info("Successfully split certificate chain: cert1=%zu bytes, cert2=%zu bytes",
             cert1_len, cert2_len);
    
    return 0;
}

int parse_reply_77_and_save(const app_cfg_t *cfg, const uint8_t *vso, size_t vso_len) {
    if (!cfg || !vso) return -1;
    
    // Find sub-option 77
    uint16_t subopt_len;
    const uint8_t *subopt_data = find_vso_subopt(vso, vso_len,
                                                 cfg->vendor.enterprise,
                                                 cfg->vendor.code_cert_reply,
                                                 &subopt_len);
    if (!subopt_data) {
        log_error("Sub-option %u not found in Reply VSO", cfg->vendor.code_cert_reply);
        return -1;
    }
    
    // Convert to null-terminated string
    char *chain_str = malloc(subopt_len + 1);
    if (!chain_str) return -1;
    
    memcpy(chain_str, subopt_data, subopt_len);
    chain_str[subopt_len] = '\0';
    
    log_info("Found certificate chain in sub-option %u (%u bytes)",
             cfg->vendor.code_cert_reply, subopt_len);
    
    // Split into two certificates
    char *cert1, *cert2;
    if (split_pem_chain(chain_str, &cert1, &cert2) != 0) {
        free(chain_str);
        return -1;
    }
    
    free(chain_str);
    
    // Validate certificates
    if (!is_valid_pem_cert(cert1) || !is_valid_pem_cert(cert2)) {
        log_error("Invalid PEM certificate format");
        free(cert1);
        free(cert2);
        return -1;
    }
    
    // Save certificates
    int ret = 0;
    
    if (write_file(cfg->paths.reply_cert0, (uint8_t*)cert1, strlen(cert1), 0640) != 0) {
        log_error("Failed to save first certificate to %s", cfg->paths.reply_cert0);
        ret = -1;
    } else {
        log_info("Saved first certificate to %s", cfg->paths.reply_cert0);
    }
    
    if (write_file(cfg->paths.reply_cert1, (uint8_t*)cert2, strlen(cert2), 0640) != 0) {
        log_error("Failed to save second certificate to %s", cfg->paths.reply_cert1);
        ret = -1;
    } else {
        log_info("Saved second certificate to %s", cfg->paths.reply_cert1);
    }
    
    // Save bundle if configured
    if (cfg->paths.reply_chain_bundle && ret == 0) {
        char *bundle = malloc(strlen(cert1) + strlen(cert2) + 2);
        if (bundle) {
            strcpy(bundle, cert1);
            strcat(bundle, "\n");
            strcat(bundle, cert2);
            
            if (write_file(cfg->paths.reply_chain_bundle, (uint8_t*)bundle,
                          strlen(bundle), 0640) == 0) {
                log_info("Saved certificate bundle to %s", cfg->paths.reply_chain_bundle);
            }
            
            free(bundle);
        }
    }
    
    free(cert1);
    free(cert2);
    
    return ret;
}