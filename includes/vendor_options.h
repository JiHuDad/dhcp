/* vendor_options.h
 *
 * DHCPv6 Vendor-Specific Options (VSO) processing library
 * Provides parsing, building, and handling of DHCPv6 Option 17
 */

/*
 * Copyright (C) 2024 Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef VENDOR_OPTIONS_H
#define VENDOR_OPTIONS_H

#include <stdint.h>
#include <stddef.h>
#include "dhcpd.h"
#include "crypto_utils.h"

/* VSO processing return codes */
#define VSO_SUCCESS            0
#define VSO_ERROR             -1
#define VSO_INVALID_DATA      -2
#define VSO_BUFFER_TOO_SMALL  -3
#define VSO_NOT_FOUND         -4
#define VSO_CRYPTO_ERROR      -5

/* Maximum sub-options per VSO */
#define VSO_MAX_SUB_OPTIONS   32

/* Common sub-option codes (can be configured) */
#define VSO_SUBOPT_SERIAL_NUMBER      71
#define VSO_SUBOPT_SIGNATURE          72
#define VSO_SUBOPT_CLIENT_CERT        73
#define VSO_SUBOPT_SIGNATURE_DUP      74
#define VSO_SUBOPT_SERVER_CERT_CHAIN  77

/* VSO sub-option structure */
struct vendor_sub_option {
    uint16_t code;
    uint16_t length;
    unsigned char *data;
};

/* VSO main structure */
struct vendor_option {
    uint32_t enterprise_num;
    int sub_option_count;
    struct vendor_sub_option sub_options[VSO_MAX_SUB_OPTIONS];
};

/* VSO configuration structure */
struct vendor_config {
    uint32_t enterprise_num;
    int enabled;
    int auto_respond;
    
    /* Cryptographic settings */
    char *private_key_path;
    char *certificate_path;
    char *ca_certificate_path;
    int require_signature;
    
    /* Sub-option configuration */
    int enabled_sub_options[256];  /* Bitmap of enabled sub-option codes */
    
    /* File paths for storing certificates */
    char *client_cert_save_path;
    char *server_cert_chain_path;
    
    /* Validation settings */
    int validate_certificates;
    int save_client_certificates;
};

/* Function prototypes */

/* Library initialization */
int vendor_options_init(void);
void vendor_options_cleanup(void);

/* VSO parsing and building */
int vendor_parse_option(const struct data_string *vso_data,
                       struct vendor_option *parsed_vso);

int vendor_build_option(const struct vendor_option *vso,
                       struct data_string *result);

int vendor_add_sub_option(struct vendor_option *vso,
                         uint16_t code, const unsigned char *data, uint16_t length);

const struct vendor_sub_option *vendor_find_sub_option(const struct vendor_option *vso,
                                                       uint16_t code);

/* DHCPv6 packet integration */
int vendor_extract_from_packet(const struct packet *packet,
                              uint32_t enterprise_num,
                              struct vendor_option *vso);

int vendor_add_to_options(struct option_state *options,
                         const struct vendor_option *vso);

/* High-level processing functions */
int vendor_process_client_request(const struct vendor_option *request_vso,
                                 const struct vendor_config *config,
                                 struct vendor_option *response_vso);

int vendor_validate_client_signature(const struct vendor_option *vso,
                                    const struct vendor_config *config,
                                    const char *expected_serial_number);

int vendor_generate_server_response(const struct vendor_config *config,
                                   const char *client_serial,
                                   struct vendor_option *response_vso);

/* Certificate handling */
int vendor_save_client_certificate(const struct vendor_sub_option *cert_subopt,
                                  const char *save_path,
                                  const char *client_id);

int vendor_load_server_certificate_chain(const char *cert_path,
                                        struct data_string *cert_chain);

int vendor_split_certificate_chain(const struct data_string *chain,
                                  struct data_string *cert1,
                                  struct data_string *cert2);

/* Signature operations */
int vendor_create_signature(const char *data,
                           const char *private_key_path,
                           struct data_string *signature);

int vendor_verify_signature(const char *data,
                           const struct data_string *signature,
                           const char *public_key_path);

int vendor_verify_signature_with_cert(const char *data,
                                     const struct data_string *signature,
                                     const struct data_string *certificate);

/* Configuration management */
int vendor_config_init(struct vendor_config *config);
void vendor_config_cleanup(struct vendor_config *config);
int vendor_config_load_from_universe(struct vendor_config *config,
                                    struct option_state *options,
                                    uint32_t enterprise_num);

/* Utility functions */
int vendor_validate_enterprise_number(uint32_t enterprise_num);
int vendor_validate_sub_option_code(uint16_t code);
const char *vendor_get_error_string(int error_code);

/* Logging and debugging */
void vendor_log_vso_contents(const struct vendor_option *vso, const char *prefix);
void vendor_log_hex_dump(const char *label, const unsigned char *data, size_t len);

/* Memory management helpers */
void vendor_option_cleanup(struct vendor_option *vso);
struct vendor_option *vendor_option_allocate(void);
void vendor_option_free(struct vendor_option *vso);

/* Packet validation */
int vendor_validate_packet_vso(const struct packet *packet,
                              uint32_t expected_enterprise);

/* Sub-option specific handlers */
int vendor_handle_serial_number(const struct vendor_sub_option *subopt,
                               char **serial_number);

int vendor_handle_signature(const struct vendor_sub_option *subopt,
                           struct data_string *signature);

int vendor_handle_certificate(const struct vendor_sub_option *subopt,
                             struct data_string *certificate);

/* Enterprise-specific handlers (can be extended) */
struct vendor_enterprise_handler {
    uint32_t enterprise_num;
    const char *name;
    
    int (*process_request)(const struct vendor_option *request,
                          const struct vendor_config *config,
                          struct vendor_option *response);
    
    int (*validate_request)(const struct vendor_option *request,
                           const struct vendor_config *config);
};

int vendor_register_enterprise_handler(const struct vendor_enterprise_handler *handler);
const struct vendor_enterprise_handler *vendor_get_enterprise_handler(uint32_t enterprise_num);

/* Constants and defaults */
#define VENDOR_DEFAULT_ENTERPRISE_NUM    0
#define VENDOR_MAX_ENTERPRISE_HANDLERS   16
#define VENDOR_MAX_SUB_OPTION_DATA_LEN   4096
#define VENDOR_MAX_VSO_DATA_LEN          65535

/* Error handling macros */
#define vendor_log_error(fmt, ...) \
    log_error("Vendor Options: " fmt, ##__VA_ARGS__)

#define vendor_log_info(fmt, ...) \
    log_info("Vendor Options: " fmt, ##__VA_ARGS__)

#define vendor_log_debug(fmt, ...) \
    log_debug("Vendor Options: " fmt, ##__VA_ARGS__)

#endif /* VENDOR_OPTIONS_H */