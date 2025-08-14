#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include "crypto.h"
#include "log.h"

struct privkey_st {
    EVP_PKEY *pkey;
};

static int crypto_initialized = 0;

int crypto_init(void) {
    if (crypto_initialized) return 0;
    
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    crypto_initialized = 1;
    return 0;
}

void crypto_cleanup(void) {
    if (!crypto_initialized) return;
    
    EVP_cleanup();
    ERR_free_strings();
    
    crypto_initialized = 0;
}

int crypto_load_private_key(const char *path, const char *passphrase, privkey_t **out) {
    if (!crypto_initialized) {
        log_error("Crypto not initialized");
        return -1;
    }
    
    FILE *fp = fopen(path, "r");
    if (!fp) {
        log_error("Failed to open private key file: %s", path);
        return -1;
    }
    
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void*)passphrase);
    fclose(fp);
    
    if (!pkey) {
        log_error("Failed to load private key from %s", path);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    // Verify it's an RSA key
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        log_error("Private key is not RSA");
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    privkey_t *key = malloc(sizeof(privkey_t));
    if (!key) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    key->pkey = pkey;
    *out = key;
    
    log_debug("Successfully loaded RSA private key from %s", path);
    return 0;
}

void crypto_free_private_key(privkey_t *key) {
    if (!key) return;
    
    if (key->pkey) {
        EVP_PKEY_free(key->pkey);
    }
    free(key);
}

int crypto_sha256(const uint8_t *in, size_t n, uint8_t out32[32]) {
    if (!crypto_initialized) return -1;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    
    int ret = -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, in, n) == 1) {
        unsigned int len = 32;
        if (EVP_DigestFinal_ex(ctx, out32, &len) == 1 && len == 32) {
            ret = 0;
        }
    }
    
    EVP_MD_CTX_free(ctx);
    return ret;
}

int crypto_rsa_sign_sha256(privkey_t *k, const uint8_t *in, size_t n,
                           uint8_t *sig, size_t *siglen) {
    if (!k || !k->pkey) return -1;
    
    // First compute SHA256 hash
    uint8_t hash[32];
    if (crypto_sha256(in, n, hash) != 0) {
        return -1;
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(k->pkey, NULL);
    if (!ctx) return -1;
    
    int ret = -1;
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        goto cleanup;
    }
    
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        goto cleanup;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        goto cleanup;
    }
    
    // First call to get required signature length
    size_t required_len = 0;
    if (EVP_PKEY_sign(ctx, NULL, &required_len, hash, 32) <= 0) {
        goto cleanup;
    }
    
    if (*siglen < required_len) {
        *siglen = required_len;
        ret = -2; // Buffer too small
        goto cleanup;
    }
    
    // Actual signing
    if (EVP_PKEY_sign(ctx, sig, siglen, hash, 32) <= 0) {
        log_error("RSA signing failed");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    ret = 0;
    log_debug("Successfully created RSA signature (%zu bytes)", *siglen);

cleanup:
    EVP_PKEY_CTX_free(ctx);
    
    // Clear sensitive data
    memset(hash, 0, sizeof(hash));
    
    return ret;
}

char *base64_encode(const uint8_t *in, size_t n) {
    if (!in || n == 0) return NULL;
    
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines
    
    BIO_write(bio, in, n);
    BIO_flush(bio);
    
    BUF_MEM *buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    char *result = malloc(buffer_ptr->length + 1);
    if (result) {
        memcpy(result, buffer_ptr->data, buffer_ptr->length);
        result[buffer_ptr->length] = '\0';
    }
    
    BIO_free_all(bio);
    return result;
}

int base64_decode(const char *in, uint8_t **out, size_t *outlen) {
    if (!in) return -1;
    
    size_t inlen = strlen(in);
    BIO *bio = BIO_new_mem_buf(in, inlen);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    // Allocate buffer (base64 decoding produces smaller output)
    uint8_t *buffer = malloc(inlen);
    if (!buffer) {
        BIO_free_all(bio);
        return -1;
    }
    
    int decoded_len = BIO_read(bio, buffer, inlen);
    BIO_free_all(bio);
    
    if (decoded_len < 0) {
        free(buffer);
        return -1;
    }
    
    *out = buffer;
    *outlen = decoded_len;
    return 0;
}