/* vendor_options.c
 *
 * DHCPv6 Vendor-Specific Options (VSO) processing implementation
 */

/*
 * Copyright (C) 2024 Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "dhcpd.h"
#include "vendor_options.h"
#include "crypto_utils.h"

#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>

/* Global state */
static int vendor_initialized = 0;
static struct vendor_enterprise_handler enterprise_handlers[VENDOR_MAX_ENTERPRISE_HANDLERS];
static int handler_count = 0;

/* Library initialization */
int vendor_options_init(void) {
    if (vendor_initialized) {
        return VSO_SUCCESS;
    }
    
    /* Initialize crypto utilities */
    if (crypto_utils_init() != CRYPTO_SUCCESS) {
        vendor_log_error("Failed to initialize crypto utilities");
        return VSO_CRYPTO_ERROR;
    }
    
    /* Clear enterprise handlers */
    memset(enterprise_handlers, 0, sizeof(enterprise_handlers));
    handler_count = 0;
    
    vendor_initialized = 1;
    vendor_log_info("Vendor options library initialized");
    
    return VSO_SUCCESS;
}

void vendor_options_cleanup(void) {
    if (!vendor_initialized) {
        return;
    }
    
    crypto_utils_cleanup();
    vendor_initialized = 0;
    vendor_log_info("Vendor options library cleaned up");
}

/* Parse VSO data into structure */
int vendor_parse_option(const struct data_string *vso_data,
                       struct vendor_option *parsed_vso) {
    const unsigned char *data;
    size_t data_len;
    size_t pos = 0;
    
    if (!vso_data || !vso_data->data || !parsed_vso) {
        return VSO_INVALID_DATA;
    }
    
    data = vso_data->data;
    data_len = vso_data->len;
    
    /* Check minimum size for enterprise number */
    if (data_len < 4) {
        vendor_log_error("VSO data too small: %zu bytes", data_len);
        return VSO_INVALID_DATA;
    }
    
    /* Initialize structure */
    memset(parsed_vso, 0, sizeof(*parsed_vso));
    
    /* Extract enterprise number (network byte order) */
    parsed_vso->enterprise_num = ntohl(*(uint32_t*)(data + pos));
    pos += 4;
    
    vendor_log_debug("Parsing VSO for enterprise %u", parsed_vso->enterprise_num);
    
    /* Parse sub-options */
    while (pos + 4 <= data_len && parsed_vso->sub_option_count < VSO_MAX_SUB_OPTIONS) {
        struct vendor_sub_option *subopt = &parsed_vso->sub_options[parsed_vso->sub_option_count];
        
        /* Extract sub-option code and length */
        subopt->code = ntohs(*(uint16_t*)(data + pos));
        pos += 2;
        subopt->length = ntohs(*(uint16_t*)(data + pos));
        pos += 2;
        
        /* Validate sub-option data length */
        if (pos + subopt->length > data_len) {
            vendor_log_error("Sub-option %u data exceeds VSO bounds", subopt->code);
            return VSO_INVALID_DATA;
        }
        
        if (subopt->length > VENDOR_MAX_SUB_OPTION_DATA_LEN) {
            vendor_log_error("Sub-option %u data too large: %u bytes", 
                           subopt->code, subopt->length);
            return VSO_INVALID_DATA;
        }
        
        /* Allocate and copy sub-option data */
        if (subopt->length > 0) {
            subopt->data = dmalloc(subopt->length, MDL);
            if (!subopt->data) {
                vendor_log_error("Failed to allocate memory for sub-option %u", subopt->code);
                vendor_option_cleanup(parsed_vso);
                return VSO_ERROR;
            }
            memcpy(subopt->data, data + pos, subopt->length);
            pos += subopt->length;
        } else {
            subopt->data = NULL;
        }
        
        vendor_log_debug("Parsed sub-option %u: %u bytes", subopt->code, subopt->length);
        parsed_vso->sub_option_count++;
    }
    
    vendor_log_info("Parsed VSO with %d sub-options for enterprise %u",
                   parsed_vso->sub_option_count, parsed_vso->enterprise_num);
    
    return VSO_SUCCESS;
}

/* Build VSO data from structure */
int vendor_build_option(const struct vendor_option *vso,
                       struct data_string *result) {
    unsigned char *buffer;
    size_t buffer_size = 0;
    size_t pos = 0;
    int i;
    
    if (!vso || !result) {
        return VSO_INVALID_DATA;
    }
    
    /* Calculate required buffer size */
    buffer_size = 4; /* Enterprise number */
    for (i = 0; i < vso->sub_option_count; i++) {
        buffer_size += 4 + vso->sub_options[i].length; /* Code + Length + Data */
    }
    
    if (buffer_size > VENDOR_MAX_VSO_DATA_LEN) {
        vendor_log_error("VSO data too large: %zu bytes", buffer_size);
        return VSO_BUFFER_TOO_SMALL;
    }
    
    /* Allocate buffer */
    buffer = dmalloc(buffer_size, MDL);
    if (!buffer) {
        vendor_log_error("Failed to allocate VSO buffer");
        return VSO_ERROR;
    }
    
    /* Write enterprise number */
    *(uint32_t*)(buffer + pos) = htonl(vso->enterprise_num);
    pos += 4;
    
    /* Write sub-options */
    for (i = 0; i < vso->sub_option_count; i++) {
        const struct vendor_sub_option *subopt = &vso->sub_options[i];
        
        /* Write sub-option code and length */
        *(uint16_t*)(buffer + pos) = htons(subopt->code);
        pos += 2;
        *(uint16_t*)(buffer + pos) = htons(subopt->length);
        pos += 2;
        
        /* Write sub-option data */
        if (subopt->length > 0 && subopt->data) {
            memcpy(buffer + pos, subopt->data, subopt->length);
            pos += subopt->length;
        }
        
        vendor_log_debug("Built sub-option %u: %u bytes", subopt->code, subopt->length);
    }
    
    /* Initialize result */
    memset(result, 0, sizeof(*result));
    result->data = buffer;
    result->len = pos;
    
    vendor_log_info("Built VSO with %d sub-options for enterprise %u (%zu bytes)",
                   vso->sub_option_count, vso->enterprise_num, pos);
    
    return VSO_SUCCESS;
}

/* Add sub-option to VSO */
int vendor_add_sub_option(struct vendor_option *vso,
                         uint16_t code, const unsigned char *data, uint16_t length) {
    struct vendor_sub_option *subopt;
    
    if (!vso) {
        return VSO_INVALID_DATA;
    }
    
    if (vso->sub_option_count >= VSO_MAX_SUB_OPTIONS) {
        vendor_log_error("Maximum sub-options reached");
        return VSO_ERROR;
    }
    
    if (length > VENDOR_MAX_SUB_OPTION_DATA_LEN) {
        vendor_log_error("Sub-option data too large: %u bytes", length);
        return VSO_INVALID_DATA;
    }
    
    subopt = &vso->sub_options[vso->sub_option_count];
    subopt->code = code;
    subopt->length = length;
    
    if (length > 0) {
        if (!data) {
            return VSO_INVALID_DATA;
        }
        
        subopt->data = dmalloc(length, MDL);
        if (!subopt->data) {
            vendor_log_error("Failed to allocate memory for sub-option %u", code);
            return VSO_ERROR;
        }
        memcpy(subopt->data, data, length);
    } else {
        subopt->data = NULL;
    }
    
    vso->sub_option_count++;
    vendor_log_debug("Added sub-option %u: %u bytes", code, length);
    
    return VSO_SUCCESS;
}

/* Find sub-option by code */
const struct vendor_sub_option *vendor_find_sub_option(const struct vendor_option *vso,
                                                       uint16_t code) {
    int i;
    
    if (!vso) {
        return NULL;
    }
    
    for (i = 0; i < vso->sub_option_count; i++) {
        if (vso->sub_options[i].code == code) {
            return &vso->sub_options[i];
        }
    }
    
    return NULL;
}

/* Extract VSO from DHCPv6 packet */
int vendor_extract_from_packet(const struct packet *packet,
                              uint32_t enterprise_num,
                              struct vendor_option *vso) {
    struct option_cache *oc;
    struct data_string vso_data;
    int result;
    
    if (!packet || !vso) {
        return VSO_INVALID_DATA;
    }
    
    /* Look for vendor-specific information option (17) */
    oc = lookup_option(&dhcpv6_universe, packet->options, D6O_VENDOR_OPTS);
    if (!oc) {
        vendor_log_debug("No vendor-specific option found in packet");
        return VSO_NOT_FOUND;
    }
    
    /* Evaluate the option data */
    memset(&vso_data, 0, sizeof(vso_data));
    if (!evaluate_option_cache(&vso_data, packet, NULL, NULL, NULL,
                              NULL, &global_scope, oc, MDL)) {
        vendor_log_error("Failed to evaluate vendor-specific option");
        return VSO_ERROR;
    }
    
    /* Parse the VSO data */
    result = vendor_parse_option(&vso_data, vso);
    data_string_forget(&vso_data, MDL);
    
    if (result != VSO_SUCCESS) {
        return result;
    }
    
    /* Check enterprise number if specified */
    if (enterprise_num != 0 && vso->enterprise_num != enterprise_num) {
        vendor_log_debug("Enterprise number mismatch: got %u, expected %u",
                        vso->enterprise_num, enterprise_num);
        vendor_option_cleanup(vso);
        return VSO_NOT_FOUND;
    }
    
    return VSO_SUCCESS;
}

/* Add VSO to option state */
int vendor_add_to_options(struct option_state *options,
                         const struct vendor_option *vso) {
    struct data_string vso_data;
    struct option_cache *oc;
    int result;
    
    if (!options || !vso) {
        return VSO_INVALID_DATA;
    }
    
    /* Build VSO data */
    memset(&vso_data, 0, sizeof(vso_data));
    result = vendor_build_option(vso, &vso_data);
    if (result != VSO_SUCCESS) {
        return result;
    }
    
    /* Create option cache */
    oc = NULL;
    if (!option_cache_allocate(&oc, MDL)) {
        data_string_forget(&vso_data, MDL);
        return VSO_ERROR;
    }
    
    /* Set up the option cache */
    oc->data = vso_data;
    oc->option = dhcp_universe.options[D6O_VENDOR_OPTS];
    
    /* Save to option state */
    save_option(&dhcpv6_universe, options, oc);
    option_cache_dereference(&oc, MDL);
    
    vendor_log_debug("Added VSO to option state");
    return VSO_SUCCESS;
}

/* Configuration management */
int vendor_config_init(struct vendor_config *config) {
    if (!config) {
        return VSO_INVALID_DATA;
    }
    
    memset(config, 0, sizeof(*config));
    config->enterprise_num = VENDOR_DEFAULT_ENTERPRISE_NUM;
    config->enabled = 0;
    config->auto_respond = 0;
    config->require_signature = 1;
    config->validate_certificates = 1;
    config->save_client_certificates = 0;
    
    return VSO_SUCCESS;
}

void vendor_config_cleanup(struct vendor_config *config) {
    if (!config) {
        return;
    }
    
    if (config->private_key_path) {
        dfree(config->private_key_path, MDL);
        config->private_key_path = NULL;
    }
    
    if (config->certificate_path) {
        dfree(config->certificate_path, MDL);
        config->certificate_path = NULL;
    }
    
    if (config->ca_certificate_path) {
        dfree(config->ca_certificate_path, MDL);
        config->ca_certificate_path = NULL;
    }
    
    if (config->client_cert_save_path) {
        dfree(config->client_cert_save_path, MDL);
        config->client_cert_save_path = NULL;
    }
    
    if (config->server_cert_chain_path) {
        dfree(config->server_cert_chain_path, MDL);
        config->server_cert_chain_path = NULL;
    }
    
    memset(config, 0, sizeof(*config));
}

/* Memory management */
void vendor_option_cleanup(struct vendor_option *vso) {
    int i;
    
    if (!vso) {
        return;
    }
    
    for (i = 0; i < vso->sub_option_count; i++) {
        if (vso->sub_options[i].data) {
            dfree(vso->sub_options[i].data, MDL);
            vso->sub_options[i].data = NULL;
        }
    }
    
    memset(vso, 0, sizeof(*vso));
}

struct vendor_option *vendor_option_allocate(void) {
    struct vendor_option *vso;
    
    vso = dmalloc(sizeof(struct vendor_option), MDL);
    if (vso) {
        memset(vso, 0, sizeof(*vso));
    }
    
    return vso;
}

void vendor_option_free(struct vendor_option *vso) {
    if (vso) {
        vendor_option_cleanup(vso);
        dfree(vso, MDL);
    }
}

/* Utility functions */
int vendor_validate_enterprise_number(uint32_t enterprise_num) {
    /* Enterprise numbers should be non-zero and within valid range */
    if (enterprise_num == 0 || enterprise_num > 0xFFFFFFFF) {
        return VSO_INVALID_DATA;
    }
    return VSO_SUCCESS;
}

int vendor_validate_sub_option_code(uint16_t code) {
    /* All 16-bit values are valid sub-option codes */
    return VSO_SUCCESS;
}

const char *vendor_get_error_string(int error_code) {
    switch (error_code) {
        case VSO_SUCCESS:            return "Success";
        case VSO_ERROR:              return "General vendor option error";
        case VSO_INVALID_DATA:       return "Invalid data";
        case VSO_BUFFER_TOO_SMALL:   return "Buffer too small";
        case VSO_NOT_FOUND:          return "Option not found";
        case VSO_CRYPTO_ERROR:       return "Cryptographic error";
        default:                     return "Unknown error";
    }
}

/* Logging functions */
void vendor_log_vso_contents(const struct vendor_option *vso, const char *prefix) {
    int i;
    
    if (!vso || !prefix) {
        return;
    }
    
    vendor_log_info("%s: Enterprise %u, %d sub-options",
                   prefix, vso->enterprise_num, vso->sub_option_count);
    
    for (i = 0; i < vso->sub_option_count; i++) {
        const struct vendor_sub_option *subopt = &vso->sub_options[i];
        vendor_log_debug("%s: Sub-option %u: %u bytes",
                        prefix, subopt->code, subopt->length);
        
        if (subopt->length > 0 && subopt->data) {
            /* Log first few bytes for debugging */
            size_t log_len = (subopt->length > 16) ? 16 : subopt->length;
            char hex_buf[64];
            int j;
            
            for (j = 0; j < log_len; j++) {
                snprintf(hex_buf + (j * 2), sizeof(hex_buf) - (j * 2),
                        "%02x", subopt->data[j]);
            }
            
            vendor_log_debug("%s: Sub-option %u data: %s%s",
                           prefix, subopt->code, hex_buf,
                           (subopt->length > 16) ? "..." : "");
        }
    }
}

void vendor_log_hex_dump(const char *label, const unsigned char *data, size_t len) {
    size_t i;
    char hex_line[80];
    char ascii_line[20];
    size_t hex_pos, ascii_pos;
    
    if (!label || !data || len == 0) {
        return;
    }
    
    vendor_log_debug("=== %s (%zu bytes) ===", label, len);
    
    for (i = 0; i < len; i += 16) {
        hex_pos = 0;
        ascii_pos = 0;
        
        snprintf(hex_line + hex_pos, sizeof(hex_line) - hex_pos, "%04zx: ", i);
        hex_pos = strlen(hex_line);
        
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            unsigned char byte = data[i + j];
            
            snprintf(hex_line + hex_pos, sizeof(hex_line) - hex_pos, "%02x ", byte);
            hex_pos += 3;
            
            ascii_line[ascii_pos++] = (byte >= 32 && byte <= 126) ? byte : '.';
        }
        
        ascii_line[ascii_pos] = '\0';
        
        /* Pad hex line if necessary */
        while (hex_pos < 54) {
            hex_line[hex_pos++] = ' ';
        }
        hex_line[hex_pos] = '\0';
        
        vendor_log_debug("%s %s", hex_line, ascii_line);
    }
}

/* Enterprise handler management */
int vendor_register_enterprise_handler(const struct vendor_enterprise_handler *handler) {
    if (!handler || handler_count >= VENDOR_MAX_ENTERPRISE_HANDLERS) {
        return VSO_ERROR;
    }
    
    enterprise_handlers[handler_count] = *handler;
    handler_count++;
    
    vendor_log_info("Registered enterprise handler for %u (%s)",
                   handler->enterprise_num, handler->name ? handler->name : "unnamed");
    
    return VSO_SUCCESS;
}

const struct vendor_enterprise_handler *vendor_get_enterprise_handler(uint32_t enterprise_num) {
    int i;
    
    for (i = 0; i < handler_count; i++) {
        if (enterprise_handlers[i].enterprise_num == enterprise_num) {
            return &enterprise_handlers[i];
        }
    }
    
    return NULL;
}

/* High-level signature operations */
int vendor_create_signature(const char *data,
                           const char *private_key_path,
                           struct data_string *signature) {
    unsigned char *sig_data;
    size_t sig_len;
    char *base64_sig;
    int result;
    
    if (!data || !private_key_path || !signature) {
        return VSO_INVALID_DATA;
    }
    
    /* Create RSA signature */
    result = crypto_sign_data_with_file((const unsigned char *)data, strlen(data),
                                      private_key_path, &sig_data, &sig_len);
    if (result != CRYPTO_SUCCESS) {
        vendor_log_error("Failed to create signature: %s", crypto_get_error_string(result));
        return VSO_CRYPTO_ERROR;
    }
    
    /* Encode as Base64 */
    base64_sig = crypto_base64_encode(sig_data, sig_len);
    crypto_secure_memzero(sig_data, sig_len);
    dfree(sig_data, MDL);
    
    if (!base64_sig) {
        vendor_log_error("Failed to encode signature as Base64");
        return VSO_CRYPTO_ERROR;
    }
    
    /* Set up result */
    memset(signature, 0, sizeof(*signature));
    signature->data = (unsigned char *)base64_sig;
    signature->len = strlen(base64_sig);
    
    return VSO_SUCCESS;
}

int vendor_verify_signature(const char *data,
                           const struct data_string *signature,
                           const char *public_key_path) {
    unsigned char *sig_data;
    size_t sig_len;
    int result;
    
    if (!data || !signature || !signature->data || !public_key_path) {
        return VSO_INVALID_DATA;
    }
    
    /* Decode Base64 signature */
    result = crypto_base64_decode((const char *)signature->data, &sig_data, &sig_len);
    if (result != CRYPTO_SUCCESS) {
        vendor_log_error("Failed to decode Base64 signature");
        return VSO_CRYPTO_ERROR;
    }
    
    /* Verify signature */
    result = crypto_verify_data_with_file((const unsigned char *)data, strlen(data),
                                        sig_data, sig_len, public_key_path);
    
    crypto_secure_memzero(sig_data, sig_len);
    dfree(sig_data, MDL);
    
    if (result != CRYPTO_SUCCESS) {
        vendor_log_error("Signature verification failed: %s", crypto_get_error_string(result));
        return VSO_CRYPTO_ERROR;
    }
    
    return VSO_SUCCESS;
}