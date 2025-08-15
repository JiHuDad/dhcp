/* crypto_utils.h
 *
 * Cryptographic utilities for DHCPv6 vendor-specific options
 * Provides RSA signing/verification, Base64 encoding/decoding, and PEM certificate handling
 */

/*
 * Copyright (C) 2024 Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include "dhcpd.h"

/* Return codes */
#define CRYPTO_SUCCESS       0
#define CRYPTO_ERROR        -1
#define CRYPTO_INVALID_KEY  -2
#define CRYPTO_INVALID_DATA -3
#define CRYPTO_MEMORY_ERROR -4
#define CRYPTO_FILE_ERROR   -5

/* RSA key structure (opaque to users) */
typedef struct crypto_rsa_key crypto_rsa_key_t;

/* Function prototypes */

/* Library initialization/cleanup */
int crypto_utils_init(void);
void crypto_utils_cleanup(void);

/* RSA key management */
int crypto_load_private_key(const char *key_path, const char *passphrase, 
                           crypto_rsa_key_t **key);
int crypto_load_public_key(const char *key_path, crypto_rsa_key_t **key);
int crypto_load_public_key_from_cert(const char *cert_path, crypto_rsa_key_t **key);
void crypto_free_key(crypto_rsa_key_t *key);

/* RSA signing/verification */
int crypto_rsa_sign_sha256(crypto_rsa_key_t *private_key,
                          const unsigned char *data, size_t data_len,
                          unsigned char *signature, size_t *sig_len);

int crypto_rsa_verify_sha256(crypto_rsa_key_t *public_key,
                            const unsigned char *data, size_t data_len,
                            const unsigned char *signature, size_t sig_len);

/* High-level sign/verify with file paths */
int crypto_sign_data_with_file(const unsigned char *data, size_t data_len,
                              const char *private_key_path,
                              unsigned char **signature, size_t *sig_len);

int crypto_verify_data_with_file(const unsigned char *data, size_t data_len,
                                const unsigned char *signature, size_t sig_len,
                                const char *public_key_path);

/* Base64 encoding/decoding */
char *crypto_base64_encode(const unsigned char *data, size_t len);
int crypto_base64_decode(const char *encoded, unsigned char **decoded, size_t *decoded_len);

/* PEM certificate handling */
int crypto_load_pem_certificate(const char *path, struct data_string *cert);
int crypto_save_pem_certificate(const char *path, const struct data_string *cert, mode_t mode);
int crypto_validate_pem_format(const struct data_string *cert);
int crypto_split_pem_chain(const struct data_string *chain, 
                          struct data_string *cert1, struct data_string *cert2);

/* Certificate validation */
int crypto_verify_certificate_chain(const struct data_string *cert,
                                   const struct data_string *ca_cert);
int crypto_extract_public_key_from_cert(const struct data_string *cert,
                                       crypto_rsa_key_t **public_key);

/* Utility functions */
int crypto_secure_random(unsigned char *buffer, size_t len);
void crypto_secure_memzero(void *ptr, size_t len);
int crypto_verify_file_permissions(const char *path, mode_t expected_mode);

/* Error handling */
const char *crypto_get_error_string(int error_code);
void crypto_log_openssl_errors(void);

#endif /* CRYPTO_UTILS_H */