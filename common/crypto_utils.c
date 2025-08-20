/* crypto_utils.c
 *
 * Cryptographic utilities implementation for DHCPv6 vendor-specific options
 */

/*
 * Copyright (C) 2024 Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "dhcpd.h"
#include "crypto_utils.h"

#ifdef HAVE_OPENSSL
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_OPENSSL

/* RSA key structure */
struct crypto_rsa_key {
    EVP_PKEY *pkey;
};

static int crypto_initialized = 0;

/* Library initialization */
int crypto_utils_init(void) {
    if (crypto_initialized) {
        return CRYPTO_SUCCESS;
    }
    
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#endif
    
    crypto_initialized = 1;
    return CRYPTO_SUCCESS;
}

void crypto_utils_cleanup(void) {
    if (!crypto_initialized) {
        return;
    }
    
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    ERR_free_strings();
#endif
    
    crypto_initialized = 0;
}

/* Load private key from file */
int crypto_load_private_key(const char *key_path, const char *passphrase,
                           crypto_rsa_key_t **key) {
    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;
    crypto_rsa_key_t *result = NULL;
    
    if (!key_path || !key) {
        return CRYPTO_INVALID_DATA;
    }
    
    /* Verify file permissions for security */
    if (crypto_verify_file_permissions(key_path, 0600) != CRYPTO_SUCCESS) {
        log_error("Private key file %s has insecure permissions", key_path);
        return CRYPTO_FILE_ERROR;
    }
    
    fp = fopen(key_path, "r");
    if (!fp) {
        log_error("Cannot open private key file %s: %s", key_path, strerror(errno));
        return CRYPTO_FILE_ERROR;
    }
    
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void*)passphrase);
    fclose(fp);
    
    if (!pkey) {
        log_error("Failed to load private key from %s", key_path);
        crypto_log_openssl_errors();
        return CRYPTO_INVALID_KEY;
    }
    
    result = dmalloc(sizeof(crypto_rsa_key_t), MDL);
    if (!result) {
        EVP_PKEY_free(pkey);
        return CRYPTO_MEMORY_ERROR;
    }
    
    result->pkey = pkey;
    *key = result;
    
    return CRYPTO_SUCCESS;
}

/* Load public key from file */
int crypto_load_public_key(const char *key_path, crypto_rsa_key_t **key) {
    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;
    crypto_rsa_key_t *result = NULL;
    
    if (!key_path || !key) {
        return CRYPTO_INVALID_DATA;
    }
    
    fp = fopen(key_path, "r");
    if (!fp) {
        log_error("Cannot open public key file %s: %s", key_path, strerror(errno));
        return CRYPTO_FILE_ERROR;
    }
    
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!pkey) {
        log_error("Failed to load public key from %s", key_path);
        crypto_log_openssl_errors();
        return CRYPTO_INVALID_KEY;
    }
    
    result = dmalloc(sizeof(crypto_rsa_key_t), MDL);
    if (!result) {
        EVP_PKEY_free(pkey);
        return CRYPTO_MEMORY_ERROR;
    }
    
    result->pkey = pkey;
    *key = result;
    
    return CRYPTO_SUCCESS;
}

/* Load public key from certificate */
int crypto_load_public_key_from_cert(const char *cert_path, crypto_rsa_key_t **key) {
    FILE *fp = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    crypto_rsa_key_t *result = NULL;
    
    if (!cert_path || !key) {
        return CRYPTO_INVALID_DATA;
    }
    
    fp = fopen(cert_path, "r");
    if (!fp) {
        log_error("Cannot open certificate file %s: %s", cert_path, strerror(errno));
        return CRYPTO_FILE_ERROR;
    }
    
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!cert) {
        log_error("Failed to load certificate from %s", cert_path);
        crypto_log_openssl_errors();
        return CRYPTO_INVALID_KEY;
    }
    
    pkey = X509_get_pubkey(cert);
    X509_free(cert);
    
    if (!pkey) {
        log_error("Failed to extract public key from certificate %s", cert_path);
        crypto_log_openssl_errors();
        return CRYPTO_INVALID_KEY;
    }
    
    result = dmalloc(sizeof(crypto_rsa_key_t), MDL);
    if (!result) {
        EVP_PKEY_free(pkey);
        return CRYPTO_MEMORY_ERROR;
    }
    
    result->pkey = pkey;
    *key = result;
    
    return CRYPTO_SUCCESS;
}

/* Free RSA key */
void crypto_free_key(crypto_rsa_key_t *key) {
    if (key) {
        if (key->pkey) {
            EVP_PKEY_free(key->pkey);
        }
        dfree(key, MDL);
    }
}

/* RSA-SHA256 signing */
int crypto_rsa_sign_sha256(crypto_rsa_key_t *private_key,
                          const unsigned char *data, size_t data_len,
                          unsigned char *signature, size_t *sig_len) {
    EVP_MD_CTX *ctx = NULL;
    int result = CRYPTO_ERROR;
    
    if (!private_key || !data || !signature || !sig_len) {
        return CRYPTO_INVALID_DATA;
    }
    
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return CRYPTO_MEMORY_ERROR;
    }
    
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, private_key->pkey) <= 0) {
        goto cleanup;
    }
    
    if (EVP_DigestSignUpdate(ctx, data, data_len) <= 0) {
        goto cleanup;
    }
    
    if (EVP_DigestSignFinal(ctx, signature, sig_len) <= 0) {
        goto cleanup;
    }
    
    result = CRYPTO_SUCCESS;
    
cleanup:
    if (ctx) {
        EVP_MD_CTX_free(ctx);
    }
    
    if (result != CRYPTO_SUCCESS) {
        crypto_log_openssl_errors();
    }
    
    return result;
}

/* RSA-SHA256 verification */
int crypto_rsa_verify_sha256(crypto_rsa_key_t *public_key,
                            const unsigned char *data, size_t data_len,
                            const unsigned char *signature, size_t sig_len) {
    EVP_MD_CTX *ctx = NULL;
    int result = CRYPTO_ERROR;
    int verify_result = -1;
    
    if (!public_key || !data || !signature) {
        return CRYPTO_INVALID_DATA;
    }
    
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return CRYPTO_MEMORY_ERROR;
    }
    
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, public_key->pkey) <= 0) {
        goto cleanup;
    }
    
    if (EVP_DigestVerifyUpdate(ctx, data, data_len) <= 0) {
        goto cleanup;
    }
    
    verify_result = EVP_DigestVerifyFinal(ctx, signature, sig_len);
    if (verify_result == 1) {
        result = CRYPTO_SUCCESS;
    } else if (verify_result == 0) {
        result = CRYPTO_ERROR; /* Signature verification failed */
    } else {
        result = CRYPTO_ERROR; /* Other error */
    }
    
cleanup:
    if (ctx) {
        EVP_MD_CTX_free(ctx);
    }
    
    if (result != CRYPTO_SUCCESS && verify_result != 0) {
        crypto_log_openssl_errors();
    }
    
    return result;
}

/* High-level sign with file path */
int crypto_sign_data_with_file(const unsigned char *data, size_t data_len,
                              const char *private_key_path,
                              unsigned char **signature, size_t *sig_len) {
    crypto_rsa_key_t *key = NULL;
    unsigned char *sig_buf = NULL;
    size_t max_sig_len;
    int result;
    
    if (!data || !private_key_path || !signature || !sig_len) {
        return CRYPTO_INVALID_DATA;
    }
    
    result = crypto_load_private_key(private_key_path, NULL, &key);
    if (result != CRYPTO_SUCCESS) {
        return result;
    }
    
    /* RSA signature length is typically key size in bytes */
    max_sig_len = EVP_PKEY_size(key->pkey);
    sig_buf = dmalloc(max_sig_len, MDL);
    if (!sig_buf) {
        crypto_free_key(key);
        return CRYPTO_MEMORY_ERROR;
    }
    
    *sig_len = max_sig_len;
    result = crypto_rsa_sign_sha256(key, data, data_len, sig_buf, sig_len);
    
    if (result == CRYPTO_SUCCESS) {
        *signature = sig_buf;
    } else {
        dfree(sig_buf, MDL);
        *signature = NULL;
        *sig_len = 0;
    }
    
    crypto_free_key(key);
    return result;
}

/* High-level verify with file path */
int crypto_verify_data_with_file(const unsigned char *data, size_t data_len,
                                const unsigned char *signature, size_t sig_len,
                                const char *public_key_path) {
    crypto_rsa_key_t *key = NULL;
    int result;
    
    if (!data || !signature || !public_key_path) {
        return CRYPTO_INVALID_DATA;
    }
    
    result = crypto_load_public_key(public_key_path, &key);
    if (result != CRYPTO_SUCCESS) {
        return result;
    }
    
    result = crypto_rsa_verify_sha256(key, data, data_len, signature, sig_len);
    
    crypto_free_key(key);
    return result;
}

/* Base64 encoding */
char *crypto_base64_encode(const unsigned char *data, size_t len) {
    BIO *b64, *bio;
    BUF_MEM *bptr;
    char *result = NULL;
    
    if (!data || len == 0) {
        return NULL;
    }
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    
    BIO_get_mem_ptr(bio, &bptr);
    
    result = dmalloc(bptr->length + 1, MDL);
    if (result) {
        memcpy(result, bptr->data, bptr->length);
        result[bptr->length] = '\0';
    }
    
    BIO_free_all(bio);
    return result;
}

/* Base64 decoding */
int crypto_base64_decode(const char *encoded, unsigned char **decoded, size_t *decoded_len) {
    BIO *b64, *bio;
    size_t input_len;
    unsigned char *result = NULL;
    int len;
    
    if (!encoded || !decoded || !decoded_len) {
        return CRYPTO_INVALID_DATA;
    }
    
    input_len = strlen(encoded);
    result = dmalloc(input_len, MDL);  /* Decoded data is always smaller */
    if (!result) {
        return CRYPTO_MEMORY_ERROR;
    }
    
    bio = BIO_new_mem_buf((void*)encoded, input_len);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    len = BIO_read(bio, result, input_len);
    
    BIO_free_all(bio);
    
    if (len < 0) {
        dfree(result, MDL);
        crypto_log_openssl_errors();
        return CRYPTO_ERROR;
    }
    
    *decoded = result;
    *decoded_len = len;
    
    return CRYPTO_SUCCESS;
}

/* Load PEM certificate */
int crypto_load_pem_certificate(const char *path, struct data_string *cert) {
    FILE *fp;
    long file_size;
    unsigned char *buffer;
    size_t read_size;
    
    if (!path || !cert) {
        return CRYPTO_INVALID_DATA;
    }
    
    fp = fopen(path, "r");
    if (!fp) {
        log_error("Cannot open certificate file %s: %s", path, strerror(errno));
        return CRYPTO_FILE_ERROR;
    }
    
    /* Get file size */
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 1024 * 1024) { /* Sanity check: max 1MB */
        fclose(fp);
        log_error("Certificate file %s has invalid size: %ld", path, file_size);
        return CRYPTO_INVALID_DATA;
    }
    
    buffer = dmalloc(file_size + 1, MDL);
    if (!buffer) {
        fclose(fp);
        return CRYPTO_MEMORY_ERROR;
    }
    
    read_size = fread(buffer, 1, file_size, fp);
    fclose(fp);
    
    if (read_size != (size_t)file_size) {
        dfree(buffer, MDL);
        log_error("Failed to read certificate file %s", path);
        return CRYPTO_FILE_ERROR;
    }
    
    buffer[file_size] = '\0'; /* Null terminate for safety */
    
    memset(cert, 0, sizeof(*cert));
    cert->data = buffer;
    cert->len = file_size;
    
    return CRYPTO_SUCCESS;
}

/* Save PEM certificate */
int crypto_save_pem_certificate(const char *path, const struct data_string *cert, mode_t mode) {
    FILE *fp;
    size_t written;
    int fd;
    
    if (!path || !cert || !cert->data) {
        return CRYPTO_INVALID_DATA;
    }
    
    /* Create file with secure permissions */
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        log_error("Cannot create certificate file %s: %s", path, strerror(errno));
        return CRYPTO_FILE_ERROR;
    }
    
    fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        log_error("Cannot open certificate file %s for writing: %s", path, strerror(errno));
        return CRYPTO_FILE_ERROR;
    }
    
    written = fwrite(cert->data, 1, cert->len, fp);
    fclose(fp);
    
    if (written != cert->len) {
        log_error("Failed to write complete certificate to %s", path);
        return CRYPTO_FILE_ERROR;
    }
    
    return CRYPTO_SUCCESS;
}

/* Validate PEM format */
int crypto_validate_pem_format(const struct data_string *cert) {
    const char *begin_marker = "-----BEGIN CERTIFICATE-----";
    const char *end_marker = "-----END CERTIFICATE-----";
    const char *data;
    
    if (!cert || !cert->data || cert->len == 0) {
        return CRYPTO_INVALID_DATA;
    }
    
    data = (const char *)cert->data;
    
    if (!strstr(data, begin_marker) || !strstr(data, end_marker)) {
        return CRYPTO_INVALID_DATA;
    }
    
    return CRYPTO_SUCCESS;
}

/* Utility functions */
int crypto_secure_random(unsigned char *buffer, size_t len) {
    if (!buffer || len == 0) {
        return CRYPTO_INVALID_DATA;
    }
    
    if (RAND_bytes(buffer, len) != 1) {
        crypto_log_openssl_errors();
        return CRYPTO_ERROR;
    }
    
    return CRYPTO_SUCCESS;
}

void crypto_secure_memzero(void *ptr, size_t len) {
    if (ptr && len > 0) {
#ifdef OPENSSL_cleanse
        OPENSSL_cleanse(ptr, len);
#else
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (len--) {
            *p++ = 0;
        }
#endif
    }
}

int crypto_verify_file_permissions(const char *path, mode_t expected_mode) {
    struct stat st;
    
    if (!path) {
        return CRYPTO_INVALID_DATA;
    }
    
    if (stat(path, &st) != 0) {
        return CRYPTO_FILE_ERROR;
    }
    
    if ((st.st_mode & 0777) != expected_mode) {
        return CRYPTO_FILE_ERROR;
    }
    
    return CRYPTO_SUCCESS;
}

const char *crypto_get_error_string(int error_code) {
    switch (error_code) {
        case CRYPTO_SUCCESS:       return "Success";
        case CRYPTO_ERROR:         return "General cryptographic error";
        case CRYPTO_INVALID_KEY:   return "Invalid key";
        case CRYPTO_INVALID_DATA:  return "Invalid data";
        case CRYPTO_MEMORY_ERROR:  return "Memory allocation error";
        case CRYPTO_FILE_ERROR:    return "File operation error";
        default:                   return "Unknown error";
    }
}

void crypto_log_openssl_errors(void) {
    unsigned long err;
    char err_buf[256];
    
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        log_error("OpenSSL error: %s", err_buf);
    }
}

#else /* !HAVE_OPENSSL */

/* Stub implementations when OpenSSL is not available */

int crypto_utils_init(void) {
    log_error("Crypto utilities not available: OpenSSL not compiled in");
    return CRYPTO_ERROR;
}

void crypto_utils_cleanup(void) {
    /* Nothing to do */
}

int crypto_load_private_key(const char *key_path, const char *passphrase,
                           crypto_rsa_key_t **key) {
    log_error("Crypto utilities not available: OpenSSL not compiled in");
    return CRYPTO_ERROR;
}

/* ... other stub implementations would follow ... */

#endif /* HAVE_OPENSSL */