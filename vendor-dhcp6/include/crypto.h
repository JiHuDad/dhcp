#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

typedef struct privkey_st privkey_t;

int crypto_load_private_key(const char *path, const char *passphrase, privkey_t **out);
void crypto_free_private_key(privkey_t *key);

int crypto_sha256(const uint8_t *in, size_t n, uint8_t out32[32]);
int crypto_rsa_sign_sha256(privkey_t *k, const uint8_t *in, size_t n,
                           uint8_t *sig, size_t *siglen);

char *base64_encode(const uint8_t *in, size_t n); // malloc'd return, caller must free
int base64_decode(const char *in, uint8_t **out, size_t *outlen); // malloc'd out

int crypto_init(void);
void crypto_cleanup(void);

#endif // CRYPTO_H