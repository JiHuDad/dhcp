/* vendor_handler.c
 *
 * DHCPv6 Vendor-Specific Options handler for server side
 * Handles incoming VSO requests and generates appropriate responses
 */

/*
 * Copyright (C) 2024 Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "dhcpd.h"

#ifdef DHCPv6

#include "vendor_options.h"
#include "crypto_utils.h"

#include <sys/stat.h>
#include <time.h>

/* Global vendor configurations */
static struct vendor_config *vendor_configs = NULL;
static int vendor_config_count = 0;

/* Forward declarations */
static int vendor_process_enterprise_12345(const struct vendor_option *request,
                                          const struct vendor_config *config,
                                          struct vendor_option *response);

static int vendor_validate_enterprise_12345(const struct vendor_option *request,
                                           const struct vendor_config *config);

/* Default enterprise handler for enterprise 12345 (example) */
static const struct vendor_enterprise_handler default_enterprise_handler = {
    .enterprise_num = 12345,
    .name = "Default Enterprise Handler",
    .process_request = vendor_process_enterprise_12345,
    .validate_request = vendor_validate_enterprise_12345
};

/* Initialize vendor handler */
int vendor_handler_init(void) {
    int result;
    
    /* Initialize vendor options library */
    result = vendor_options_init();
    if (result != VSO_SUCCESS) {
        log_error("Failed to initialize vendor options library: %s",
                 vendor_get_error_string(result));
        return result;
    }
    
    /* Register default enterprise handler */
    result = vendor_register_enterprise_handler(&default_enterprise_handler);
    if (result != VSO_SUCCESS) {
        log_error("Failed to register default enterprise handler");
        return result;
    }
    
    log_info("Vendor handler initialized");
    return VSO_SUCCESS;
}

void vendor_handler_cleanup(void) {
    int i;
    
    /* Clean up vendor configurations */
    for (i = 0; i < vendor_config_count; i++) {
        vendor_config_cleanup(&vendor_configs[i]);
    }
    
    if (vendor_configs) {
        dfree(vendor_configs, MDL);
        vendor_configs = NULL;
    }
    
    vendor_config_count = 0;
    
    vendor_options_cleanup();
    log_info("Vendor handler cleaned up");
}

/* Load vendor configuration from option state */
int vendor_load_config(struct option_state *options,
                      uint32_t enterprise_num,
                      struct vendor_config *config) {
    
    if (!options || !config) {
        return VSO_INVALID_DATA;
    }
    
    /* Initialize config */
    vendor_config_init(config);
    config->enterprise_num = enterprise_num;
    
    /* Look for vendor-config options */
    /* This would be implemented when we add the configuration parsing */
    
    /* For now, use default configuration */
    config->enabled = 1;
    config->auto_respond = 1;
    config->require_signature = 1;
    config->validate_certificates = 1;
    config->save_client_certificates = 1;
    
    /* Default paths - these should come from configuration */
    config->private_key_path = dmalloc(256, MDL);
    config->certificate_path = dmalloc(256, MDL);
    config->client_cert_save_path = dmalloc(256, MDL);
    config->server_cert_chain_path = dmalloc(256, MDL);
    
    if (!config->private_key_path || !config->certificate_path ||
        !config->client_cert_save_path || !config->server_cert_chain_path) {
        vendor_config_cleanup(config);
        return VSO_ERROR;
    }
    
    strcpy(config->private_key_path, "/etc/dhcp/vendor/server.key");
    strcpy(config->certificate_path, "/etc/dhcp/vendor/server.pem");
    strcpy(config->client_cert_save_path, "/var/lib/dhcp/client-certs/");
    strcpy(config->server_cert_chain_path, "/etc/dhcp/vendor/cert_chain.pem");
    
    /* Enable common sub-options */
    config->enabled_sub_options[VSO_SUBOPT_SERIAL_NUMBER] = 1;
    config->enabled_sub_options[VSO_SUBOPT_SIGNATURE] = 1;
    config->enabled_sub_options[VSO_SUBOPT_CLIENT_CERT] = 1;
    config->enabled_sub_options[VSO_SUBOPT_SIGNATURE_DUP] = 1;
    config->enabled_sub_options[VSO_SUBOPT_SERVER_CERT_CHAIN] = 1;
    
    log_debug("Loaded vendor config for enterprise %u", enterprise_num);
    return VSO_SUCCESS;
}

/* Main vendor request handler */
int vendor_handle_request(struct packet *packet,
                         struct option_state *options,
                         struct option_state *reply_options) {
    struct vendor_option request_vso;
    struct vendor_option response_vso;
    struct vendor_config config;
    const struct vendor_enterprise_handler *handler;
    int result;
    
    if (!packet || !options || !reply_options) {
        return VSO_INVALID_DATA;
    }
    
    /* Extract VSO from packet */
    result = vendor_extract_from_packet(packet, 0, &request_vso);
    if (result == VSO_NOT_FOUND) {
        /* No vendor option in request - this is normal */
        return VSO_SUCCESS;
    } else if (result != VSO_SUCCESS) {
        log_error("Failed to extract vendor option from packet: %s",
                 vendor_get_error_string(result));
        return result;
    }
    
    vendor_log_vso_contents(&request_vso, "Received VSO");
    
    /* Load configuration for this enterprise */
    result = vendor_load_config(options, request_vso.enterprise_num, &config);
    if (result != VSO_SUCCESS) {
        log_error("Failed to load vendor config for enterprise %u",
                 request_vso.enterprise_num);
        vendor_option_cleanup(&request_vso);
        return result;
    }
    
    if (!config.enabled) {
        log_debug("Vendor options disabled for enterprise %u",
                 request_vso.enterprise_num);
        vendor_option_cleanup(&request_vso);
        vendor_config_cleanup(&config);
        return VSO_SUCCESS;
    }
    
    /* Find enterprise-specific handler */
    handler = vendor_get_enterprise_handler(request_vso.enterprise_num);
    if (!handler) {
        log_error("No handler found for enterprise %u", request_vso.enterprise_num);
        vendor_option_cleanup(&request_vso);
        vendor_config_cleanup(&config);
        return VSO_ERROR;
    }
    
    /* Validate request */
    if (handler->validate_request) {
        result = handler->validate_request(&request_vso, &config);
        if (result != VSO_SUCCESS) {
            log_error("Vendor request validation failed for enterprise %u: %s",
                     request_vso.enterprise_num, vendor_get_error_string(result));
            vendor_option_cleanup(&request_vso);
            vendor_config_cleanup(&config);
            return result;
        }
    }
    
    /* Process request and generate response */
    memset(&response_vso, 0, sizeof(response_vso));
    response_vso.enterprise_num = request_vso.enterprise_num;
    
    if (handler->process_request) {
        result = handler->process_request(&request_vso, &config, &response_vso);
        if (result != VSO_SUCCESS) {
            log_error("Failed to process vendor request for enterprise %u: %s",
                     request_vso.enterprise_num, vendor_get_error_string(result));
            vendor_option_cleanup(&request_vso);
            vendor_option_cleanup(&response_vso);
            vendor_config_cleanup(&config);
            return result;
        }
    }
    
    /* Add response to reply options if we have one */
    if (response_vso.sub_option_count > 0) {
        result = vendor_add_to_options(reply_options, &response_vso);
        if (result != VSO_SUCCESS) {
            log_error("Failed to add vendor response to options: %s",
                     vendor_get_error_string(result));
        } else {
            vendor_log_vso_contents(&response_vso, "Generated VSO response");
        }
    }
    
    /* Cleanup */
    vendor_option_cleanup(&request_vso);
    vendor_option_cleanup(&response_vso);
    vendor_config_cleanup(&config);
    
    return result;
}

/* Enterprise 12345 specific request processor */
static int vendor_process_enterprise_12345(const struct vendor_option *request,
                                          const struct vendor_config *config,
                                          struct vendor_option *response) {
    const struct vendor_sub_option *serial_subopt;
    const struct vendor_sub_option *sig_subopt;
    const struct vendor_sub_option *cert_subopt;
    char *serial_number = NULL;
    struct data_string signature;
    struct data_string client_cert;
    struct data_string server_cert_chain;
    int result = VSO_SUCCESS;
    char client_id[256];
    
    if (!request || !config || !response) {
        return VSO_INVALID_DATA;
    }
    
    memset(&signature, 0, sizeof(signature));
    memset(&client_cert, 0, sizeof(client_cert));
    memset(&server_cert_chain, 0, sizeof(server_cert_chain));
    
    /* Extract serial number (sub-option 71) */
    serial_subopt = vendor_find_sub_option(request, VSO_SUBOPT_SERIAL_NUMBER);
    if (!serial_subopt) {
        log_error("Serial number sub-option not found");
        return VSO_INVALID_DATA;
    }
    
    serial_number = dmalloc(serial_subopt->length + 1, MDL);
    if (!serial_number) {
        return VSO_ERROR;
    }
    memcpy(serial_number, serial_subopt->data, serial_subopt->length);
    serial_number[serial_subopt->length] = '\0';
    
    log_info("Processing request for serial number: %.8s...", serial_number);
    
    /* Verify signature if required (sub-option 72) */
    if (config->require_signature) {
        sig_subopt = vendor_find_sub_option(request, VSO_SUBOPT_SIGNATURE);
        if (!sig_subopt) {
            log_error("Signature sub-option not found but required");
            result = VSO_INVALID_DATA;
            goto cleanup;
        }
        
        signature.data = dmalloc(sig_subopt->length + 1, MDL);
        if (!signature.data) {
            result = VSO_ERROR;
            goto cleanup;
        }
        memcpy((void*)signature.data, sig_subopt->data, sig_subopt->length);
        ((unsigned char*)signature.data)[sig_subopt->length] = '\0';
        signature.len = sig_subopt->length;
        
        /* Verify signature using client certificate */
        cert_subopt = vendor_find_sub_option(request, VSO_SUBOPT_CLIENT_CERT);
        if (cert_subopt) {
            client_cert.data = dmalloc(cert_subopt->length, MDL);
            if (!client_cert.data) {
                result = VSO_ERROR;
                goto cleanup;
            }
            memcpy((void*)client_cert.data, cert_subopt->data, cert_subopt->length);
            client_cert.len = cert_subopt->length;
            
            result = vendor_verify_signature_with_cert(serial_number, &signature, &client_cert);
            if (result != VSO_SUCCESS) {
                log_error("Signature verification failed");
                goto cleanup;
            }
            
            log_info("Signature verification successful");
            
            /* Save client certificate if configured */
            if (config->save_client_certificates) {
                snprintf(client_id, sizeof(client_id), "%s", serial_number);
                vendor_save_client_certificate(cert_subopt, 
                                              config->client_cert_save_path, 
                                              client_id);
            }
        }
    }
    
    /* Generate server response (sub-option 77) */
    if (config->auto_respond) {
        result = vendor_load_server_certificate_chain(config->server_cert_chain_path,
                                                     &server_cert_chain);
        if (result == VSO_SUCCESS) {
            result = vendor_add_sub_option(response, VSO_SUBOPT_SERVER_CERT_CHAIN,
                                         server_cert_chain.data, server_cert_chain.len);
            if (result == VSO_SUCCESS) {
                log_info("Added server certificate chain to response");
            }
        } else {
            log_error("Failed to load server certificate chain: %s",
                     vendor_get_error_string(result));
        }
    }
    
cleanup:
    if (serial_number) {
        dfree(serial_number, MDL);
    }
    
    if (signature.data) {
        data_string_forget(&signature, MDL);
    }
    
    if (client_cert.data) {
        data_string_forget(&client_cert, MDL);
    }
    
    if (server_cert_chain.data) {
        data_string_forget(&server_cert_chain, MDL);
    }
    
    return result;
}

/* Enterprise 12345 specific request validator */
static int vendor_validate_enterprise_12345(const struct vendor_option *request,
                                           const struct vendor_config *config) {
    const struct vendor_sub_option *serial_subopt;
    const struct vendor_sub_option *sig_subopt;
    const struct vendor_sub_option *cert_subopt;
    
    if (!request || !config) {
        return VSO_INVALID_DATA;
    }
    
    /* Check for required sub-options */
    serial_subopt = vendor_find_sub_option(request, VSO_SUBOPT_SERIAL_NUMBER);
    if (!serial_subopt) {
        log_error("Missing required serial number sub-option");
        return VSO_INVALID_DATA;
    }
    
    /* Validate serial number format */
    if (serial_subopt->length == 0 || serial_subopt->length > 64) {
        log_error("Invalid serial number length: %u", serial_subopt->length);
        return VSO_INVALID_DATA;
    }
    
    /* Check signature if required */
    if (config->require_signature) {
        sig_subopt = vendor_find_sub_option(request, VSO_SUBOPT_SIGNATURE);
        if (!sig_subopt) {
            log_error("Missing required signature sub-option");
            return VSO_INVALID_DATA;
        }
        
        cert_subopt = vendor_find_sub_option(request, VSO_SUBOPT_CLIENT_CERT);
        if (!cert_subopt) {
            log_error("Missing required client certificate sub-option");
            return VSO_INVALID_DATA;
        }
        
        /* Validate certificate format */
        struct data_string cert_data;
        cert_data.data = cert_subopt->data;
        cert_data.len = cert_subopt->length;
        
        if (crypto_validate_pem_format(&cert_data) != CRYPTO_SUCCESS) {
            log_error("Invalid client certificate format");
            return VSO_INVALID_DATA;
        }
    }
    
    log_debug("Vendor request validation passed for enterprise 12345");
    return VSO_SUCCESS;
}

/* Save client certificate to file */
int vendor_save_client_certificate(const struct vendor_sub_option *cert_subopt,
                                  const char *save_path,
                                  const char *client_id) {
    char cert_file_path[PATH_MAX];
    struct data_string cert_data;
    struct stat st;
    int result;
    
    if (!cert_subopt || !save_path || !client_id) {
        return VSO_INVALID_DATA;
    }
    
    /* Create directory if it doesn't exist */
    if (stat(save_path, &st) != 0) {
        if (mkdir(save_path, 0755) != 0) {
            log_error("Failed to create certificate save directory %s: %s",
                     save_path, strerror(errno));
            return VSO_ERROR;
        }
    }
    
    /* Construct certificate file path */
    snprintf(cert_file_path, sizeof(cert_file_path), "%s/client_%s.pem",
             save_path, client_id);
    
    /* Set up certificate data */
    cert_data.data = cert_subopt->data;
    cert_data.len = cert_subopt->length;
    
    /* Save certificate */
    result = crypto_save_pem_certificate(cert_file_path, &cert_data, 0644);
    if (result != CRYPTO_SUCCESS) {
        log_error("Failed to save client certificate to %s: %s",
                 cert_file_path, crypto_get_error_string(result));
        return VSO_ERROR;
    }
    
    log_info("Saved client certificate to %s", cert_file_path);
    return VSO_SUCCESS;
}

/* Load server certificate chain */
int vendor_load_server_certificate_chain(const char *cert_path,
                                        struct data_string *cert_chain) {
    int result;
    
    if (!cert_path || !cert_chain) {
        return VSO_INVALID_DATA;
    }
    
    result = crypto_load_pem_certificate(cert_path, cert_chain);
    if (result != CRYPTO_SUCCESS) {
        log_error("Failed to load server certificate chain from %s: %s",
                 cert_path, crypto_get_error_string(result));
        return VSO_ERROR;
    }
    
    /* Validate certificate format */
    result = crypto_validate_pem_format(cert_chain);
    if (result != CRYPTO_SUCCESS) {
        log_error("Invalid server certificate chain format in %s", cert_path);
        data_string_forget(cert_chain, MDL);
        return VSO_INVALID_DATA;
    }
    
    log_debug("Loaded server certificate chain from %s (%u bytes)",
             cert_path, cert_chain->len);
    
    return VSO_SUCCESS;
}

/* Verify signature with certificate */
int vendor_verify_signature_with_cert(const char *data,
                                     const struct data_string *signature,
                                     const struct data_string *certificate) {
    crypto_rsa_key_t *public_key = NULL;
    unsigned char *sig_data = NULL;
    size_t sig_len;
    int result;
    
    if (!data || !signature || !certificate) {
        return VSO_INVALID_DATA;
    }
    
    /* Extract public key from certificate */
    result = crypto_extract_public_key_from_cert(certificate, &public_key);
    if (result != CRYPTO_SUCCESS) {
        log_error("Failed to extract public key from certificate");
        return VSO_CRYPTO_ERROR;
    }
    
    /* Decode Base64 signature */
    result = crypto_base64_decode((const char *)signature->data, &sig_data, &sig_len);
    if (result != CRYPTO_SUCCESS) {
        log_error("Failed to decode signature");
        crypto_free_key(public_key);
        return VSO_CRYPTO_ERROR;
    }
    
    /* Verify signature */
    result = crypto_rsa_verify_sha256(public_key,
                                    (const unsigned char *)data, strlen(data),
                                    sig_data, sig_len);
    
    /* Cleanup */
    crypto_free_key(public_key);
    crypto_secure_memzero(sig_data, sig_len);
    dfree(sig_data, MDL);
    
    if (result != CRYPTO_SUCCESS) {
        log_error("Signature verification failed");
        return VSO_CRYPTO_ERROR;
    }
    
    return VSO_SUCCESS;
}

#endif /* DHCPv6 */