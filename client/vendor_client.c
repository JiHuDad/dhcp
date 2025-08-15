/* vendor_client.c
 *
 * DHCPv6 Vendor-Specific Options client-side handler
 * Handles VSO generation for requests and processing of server responses
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
#include <stdlib.h>
#include <time.h>

/* Client vendor configuration */
struct client_vendor_config {
    uint32_t enterprise_num;
    int enabled;
    
    /* Client authentication */
    char *serial_number_env;
    char *private_key_path;
    char *request_certificate_path;
    
    /* Response handling */
    char *save_certificates_path;
    int verify_signature;
    
    /* Sub-option configuration */
    int request_sub_options[256];
    int expect_sub_options[256];
};

static struct client_vendor_config client_config;
static int client_vendor_initialized = 0;

/* Forward declarations */
static int client_load_config(void);
static int client_generate_request_vso(struct vendor_option *vso);
static int client_process_reply_vso(const struct vendor_option *vso);
static int client_save_server_certificates(const struct vendor_sub_option *cert_subopt);

/* Initialize client vendor handler */
int client_vendor_init(void) {
    int result;
    
    if (client_vendor_initialized) {
        return VSO_SUCCESS;
    }
    
    /* Initialize vendor options library */
    result = vendor_options_init();
    if (result != VSO_SUCCESS) {
        log_error("Failed to initialize vendor options library: %s",
                 vendor_get_error_string(result));
        return result;
    }
    
    /* Load client configuration */
    result = client_load_config();
    if (result != VSO_SUCCESS) {
        log_error("Failed to load client vendor configuration");
        return result;
    }
    
    client_vendor_initialized = 1;
    log_info("Client vendor handler initialized for enterprise %u",
             client_config.enterprise_num);
    
    return VSO_SUCCESS;
}

void client_vendor_cleanup(void) {
    if (!client_vendor_initialized) {
        return;
    }
    
    /* Clean up configuration */
    if (client_config.serial_number_env) {
        dfree(client_config.serial_number_env, MDL);
        client_config.serial_number_env = NULL;
    }
    
    if (client_config.private_key_path) {
        dfree(client_config.private_key_path, MDL);
        client_config.private_key_path = NULL;
    }
    
    if (client_config.request_certificate_path) {
        dfree(client_config.request_certificate_path, MDL);
        client_config.request_certificate_path = NULL;
    }
    
    if (client_config.save_certificates_path) {
        dfree(client_config.save_certificates_path, MDL);
        client_config.save_certificates_path = NULL;
    }
    
    memset(&client_config, 0, sizeof(client_config));
    
    vendor_options_cleanup();
    client_vendor_initialized = 0;
    
    log_info("Client vendor handler cleaned up");
}

/* Load client vendor configuration */
static int client_load_config(void) {
    const char *env_value;
    
    /* Initialize default configuration */
    memset(&client_config, 0, sizeof(client_config));
    
    /* Default enterprise number (would normally come from config file) */
    client_config.enterprise_num = 12345;
    client_config.enabled = 1;
    client_config.verify_signature = 1;
    
    /* Serial number environment variable */
    client_config.serial_number_env = dmalloc(32, MDL);
    if (!client_config.serial_number_env) {
        return VSO_ERROR;
    }
    strcpy(client_config.serial_number_env, "SN_NUMBER");
    
    /* Default paths */
    client_config.private_key_path = dmalloc(256, MDL);
    client_config.request_certificate_path = dmalloc(256, MDL);
    client_config.save_certificates_path = dmalloc(256, MDL);
    
    if (!client_config.private_key_path || 
        !client_config.request_certificate_path ||
        !client_config.save_certificates_path) {
        return VSO_ERROR;
    }
    
    strcpy(client_config.private_key_path, "/etc/dhcp/client.key");
    strcpy(client_config.request_certificate_path, "/etc/dhcp/client_request.pem");
    strcpy(client_config.save_certificates_path, "/var/lib/dhcp/server-certs/");
    
    /* Configure sub-options to request */
    client_config.request_sub_options[VSO_SUBOPT_SERIAL_NUMBER] = 1;
    client_config.request_sub_options[VSO_SUBOPT_SIGNATURE] = 1;
    client_config.request_sub_options[VSO_SUBOPT_CLIENT_CERT] = 1;
    client_config.request_sub_options[VSO_SUBOPT_SIGNATURE_DUP] = 1;
    
    /* Configure sub-options to expect in response */
    client_config.expect_sub_options[VSO_SUBOPT_SERVER_CERT_CHAIN] = 1;
    
    /* Check if vendor options are enabled via environment */
    env_value = getenv("DHCP_VENDOR_OPTIONS");
    if (env_value && (strcmp(env_value, "0") == 0 || strcmp(env_value, "false") == 0)) {
        client_config.enabled = 0;
        log_info("Vendor options disabled via environment variable");
    }
    
    log_debug("Client vendor config loaded: enterprise=%u, enabled=%d",
             client_config.enterprise_num, client_config.enabled);
    
    return VSO_SUCCESS;
}

/* Generate VSO for client request */
int client_vendor_generate_request(struct option_state *options) {
    struct vendor_option vso;
    int result;
    
    if (!client_vendor_initialized || !client_config.enabled) {
        return VSO_SUCCESS; /* Not an error, just disabled */
    }
    
    if (!options) {
        return VSO_INVALID_DATA;
    }
    
    /* Generate request VSO */
    memset(&vso, 0, sizeof(vso));
    result = client_generate_request_vso(&vso);
    if (result != VSO_SUCCESS) {
        log_error("Failed to generate client request VSO: %s",
                 vendor_get_error_string(result));
        return result;
    }
    
    /* Add VSO to options */
    result = vendor_add_to_options(options, &vso);
    if (result != VSO_SUCCESS) {
        log_error("Failed to add VSO to client request options: %s",
                 vendor_get_error_string(result));
        vendor_option_cleanup(&vso);
        return result;
    }
    
    vendor_log_vso_contents(&vso, "Client Request VSO");
    vendor_option_cleanup(&vso);
    
    log_info("Generated client vendor request for enterprise %u",
             client_config.enterprise_num);
    
    return VSO_SUCCESS;
}

/* Process VSO from server reply */
int client_vendor_process_reply(struct packet *packet) {
    struct vendor_option vso;
    int result;
    
    if (!client_vendor_initialized || !client_config.enabled) {
        return VSO_SUCCESS; /* Not an error, just disabled */
    }
    
    if (!packet) {
        return VSO_INVALID_DATA;
    }
    
    /* Extract VSO from reply packet */
    result = vendor_extract_from_packet(packet, client_config.enterprise_num, &vso);
    if (result == VSO_NOT_FOUND) {
        log_debug("No vendor option in server reply");
        return VSO_SUCCESS; /* No VSO is fine */
    } else if (result != VSO_SUCCESS) {
        log_error("Failed to extract VSO from server reply: %s",
                 vendor_get_error_string(result));
        return result;
    }
    
    vendor_log_vso_contents(&vso, "Server Reply VSO");
    
    /* Process the reply VSO */
    result = client_process_reply_vso(&vso);
    if (result != VSO_SUCCESS) {
        log_error("Failed to process server reply VSO: %s",
                 vendor_get_error_string(result));
    } else {
        log_info("Successfully processed server vendor reply");
    }
    
    vendor_option_cleanup(&vso);
    return result;
}

/* Generate request VSO with client credentials */
static int client_generate_request_vso(struct vendor_option *vso) {
    const char *serial_number;
    struct data_string signature;
    struct data_string client_cert;
    int result = VSO_SUCCESS;
    
    if (!vso) {
        return VSO_INVALID_DATA;
    }
    
    memset(&signature, 0, sizeof(signature));
    memset(&client_cert, 0, sizeof(client_cert));
    
    /* Initialize VSO */
    vso->enterprise_num = client_config.enterprise_num;
    vso->sub_option_count = 0;
    
    /* Get serial number from environment */
    serial_number = getenv(client_config.serial_number_env);
    if (!serial_number) {
        log_error("Environment variable %s not set", client_config.serial_number_env);
        return VSO_INVALID_DATA;
    }
    
    log_info("Using serial number: %.8s... (%zu chars)", 
             serial_number, strlen(serial_number));
    
    /* Add serial number sub-option (71) */
    result = vendor_add_sub_option(vso, VSO_SUBOPT_SERIAL_NUMBER,
                                  (const unsigned char *)serial_number,
                                  strlen(serial_number));
    if (result != VSO_SUCCESS) {
        goto cleanup;
    }
    
    /* Create signature sub-option (72) */
    result = vendor_create_signature(serial_number,
                                   client_config.private_key_path,
                                   &signature);
    if (result != VSO_SUCCESS) {
        log_error("Failed to create signature");
        goto cleanup;
    }
    
    result = vendor_add_sub_option(vso, VSO_SUBOPT_SIGNATURE,
                                  signature.data, signature.len);
    if (result != VSO_SUCCESS) {
        goto cleanup;
    }
    
    log_info("Created signature: %.8s... (%u bytes)", signature.data, signature.len);
    
    /* Add client certificate sub-option (73) */
    result = crypto_load_pem_certificate(client_config.request_certificate_path,
                                       &client_cert);
    if (result == CRYPTO_SUCCESS) {
        result = vendor_add_sub_option(vso, VSO_SUBOPT_CLIENT_CERT,
                                      client_cert.data, client_cert.len);
        if (result == VSO_SUCCESS) {
            log_info("Added client certificate (%u bytes)", client_cert.len);
        }
    } else {
        log_warn("Failed to load client certificate from %s: %s",
                client_config.request_certificate_path,
                crypto_get_error_string(result));
        /* Continue without certificate - not always required */
        result = VSO_SUCCESS;
    }
    
    /* Add duplicate signature sub-option (74) */
    if (signature.data && signature.len > 0) {
        int dup_result = vendor_add_sub_option(vso, VSO_SUBOPT_SIGNATURE_DUP,
                                              signature.data, signature.len);
        if (dup_result != VSO_SUCCESS) {
            log_warn("Failed to add duplicate signature sub-option");
            /* Continue - duplicate signature is optional */
        }
    }
    
cleanup:
    if (signature.data) {
        data_string_forget(&signature, MDL);
    }
    
    if (client_cert.data) {
        data_string_forget(&client_cert, MDL);
    }
    
    return result;
}

/* Process reply VSO from server */
static int client_process_reply_vso(const struct vendor_option *vso) {
    const struct vendor_sub_option *cert_subopt;
    int result = VSO_SUCCESS;
    
    if (!vso) {
        return VSO_INVALID_DATA;
    }
    
    /* Look for server certificate chain (sub-option 77) */
    cert_subopt = vendor_find_sub_option(vso, VSO_SUBOPT_SERVER_CERT_CHAIN);
    if (!cert_subopt) {
        log_debug("No server certificate chain in reply");
        return VSO_SUCCESS; /* Not necessarily an error */
    }
    
    log_info("Found server certificate chain (%u bytes)", cert_subopt->length);
    
    /* Save server certificates */
    result = client_save_server_certificates(cert_subopt);
    if (result != VSO_SUCCESS) {
        log_error("Failed to save server certificates");
        return result;
    }
    
    /* Verify certificate chain if required */
    if (client_config.verify_signature) {
        struct data_string cert_data;
        cert_data.data = cert_subopt->data;
        cert_data.len = cert_subopt->length;
        
        result = crypto_validate_pem_format(&cert_data);
        if (result != CRYPTO_SUCCESS) {
            log_error("Invalid server certificate format");
            return VSO_INVALID_DATA;
        } else {
            log_info("Server certificate format validation passed");
        }
    }
    
    return VSO_SUCCESS;
}

/* Save server certificates from reply */
static int client_save_server_certificates(const struct vendor_sub_option *cert_subopt) {
    struct data_string cert_chain;
    struct data_string cert1, cert2;
    char cert_file_path[PATH_MAX];
    char bundle_file_path[PATH_MAX];
    struct stat st;
    int result;
    time_t now;
    struct tm *tm_info;
    char timestamp[32];
    
    if (!cert_subopt) {
        return VSO_INVALID_DATA;
    }
    
    /* Create directory if it doesn't exist */
    if (stat(client_config.save_certificates_path, &st) != 0) {
        if (mkdir(client_config.save_certificates_path, 0755) != 0) {
            log_error("Failed to create certificate save directory %s: %s",
                     client_config.save_certificates_path, strerror(errno));
            return VSO_ERROR;
        }
    }
    
    /* Set up certificate data */
    cert_chain.data = cert_subopt->data;
    cert_chain.len = cert_subopt->length;
    
    memset(&cert1, 0, sizeof(cert1));
    memset(&cert2, 0, sizeof(cert2));
    
    /* Try to split certificate chain */
    result = vendor_split_certificate_chain(&cert_chain, &cert1, &cert2);
    if (result == VSO_SUCCESS) {
        /* Save individual certificates */
        snprintf(cert_file_path, sizeof(cert_file_path), 
                "%s/server_cert1.pem", client_config.save_certificates_path);
        
        result = crypto_save_pem_certificate(cert_file_path, &cert1, 0644);
        if (result == CRYPTO_SUCCESS) {
            log_info("Saved server certificate 1 to %s", cert_file_path);
        }
        
        snprintf(cert_file_path, sizeof(cert_file_path),
                "%s/server_cert2.pem", client_config.save_certificates_path);
        
        result = crypto_save_pem_certificate(cert_file_path, &cert2, 0644);
        if (result == CRYPTO_SUCCESS) {
            log_info("Saved server certificate 2 to %s", cert_file_path);
        }
        
        data_string_forget(&cert1, MDL);
        data_string_forget(&cert2, MDL);
    }
    
    /* Save complete certificate chain with timestamp */
    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    
    snprintf(bundle_file_path, sizeof(bundle_file_path),
            "%s/server_chain_%s.pem", client_config.save_certificates_path, timestamp);
    
    result = crypto_save_pem_certificate(bundle_file_path, &cert_chain, 0644);
    if (result == CRYPTO_SUCCESS) {
        log_info("Saved server certificate chain to %s", bundle_file_path);
    } else {
        log_error("Failed to save server certificate chain to %s: %s",
                 bundle_file_path, crypto_get_error_string(result));
        return VSO_ERROR;
    }
    
    return VSO_SUCCESS;
}

/* Check if vendor options are enabled for client */
int client_vendor_enabled(void) {
    return (client_vendor_initialized && client_config.enabled);
}

/* Get client enterprise number */
uint32_t client_vendor_get_enterprise_num(void) {
    if (client_vendor_initialized) {
        return client_config.enterprise_num;
    }
    return 0;
}

/* Set client vendor configuration (for testing or dynamic config) */
int client_vendor_set_config(uint32_t enterprise_num, const char *serial_env,
                            const char *private_key, const char *cert_path) {
    if (!client_vendor_initialized) {
        return VSO_ERROR;
    }
    
    client_config.enterprise_num = enterprise_num;
    
    if (serial_env) {
        if (client_config.serial_number_env) {
            dfree(client_config.serial_number_env, MDL);
        }
        client_config.serial_number_env = dmalloc(strlen(serial_env) + 1, MDL);
        if (client_config.serial_number_env) {
            strcpy(client_config.serial_number_env, serial_env);
        }
    }
    
    if (private_key) {
        if (client_config.private_key_path) {
            dfree(client_config.private_key_path, MDL);
        }
        client_config.private_key_path = dmalloc(strlen(private_key) + 1, MDL);
        if (client_config.private_key_path) {
            strcpy(client_config.private_key_path, private_key);
        }
    }
    
    if (cert_path) {
        if (client_config.request_certificate_path) {
            dfree(client_config.request_certificate_path, MDL);
        }
        client_config.request_certificate_path = dmalloc(strlen(cert_path) + 1, MDL);
        if (client_config.request_certificate_path) {
            strcpy(client_config.request_certificate_path, cert_path);
        }
    }
    
    log_info("Updated client vendor configuration: enterprise=%u", enterprise_num);
    return VSO_SUCCESS;
}

#endif /* DHCPv6 */