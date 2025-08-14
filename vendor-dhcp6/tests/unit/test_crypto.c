#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto.h"

void test_sha256() {
    printf("Testing SHA256...\n");
    
    const char *test_input = "Hello, World!";
    uint8_t hash[32];
    
    assert(crypto_init() == 0);
    assert(crypto_sha256((uint8_t*)test_input, strlen(test_input), hash) == 0);
    
    // Expected SHA256 of "Hello, World!"
    uint8_t expected[] = {
        0xdf, 0xfd, 0x60, 0x21, 0xbb, 0x2b, 0xd5, 0xb0,
        0xaf, 0x67, 0x62, 0x90, 0x80, 0x9e, 0xc3, 0xa5,
        0x31, 0x91, 0xdd, 0x81, 0xc7, 0xf7, 0x0a, 0x4b,
        0x28, 0x68, 0x8a, 0x36, 0x21, 0x82, 0x98, 0x6f
    };
    
    assert(memcmp(hash, expected, 32) == 0);
    printf("✓ SHA256 test passed\n");
    
    crypto_cleanup();
}

void test_base64() {
    printf("Testing Base64...\n");
    
    const char *test_input = "Hello, Base64!";
    char *encoded = base64_encode((uint8_t*)test_input, strlen(test_input));
    
    assert(encoded != NULL);
    assert(strcmp(encoded, "SGVsbG8sIEJhc2U2NCE=") == 0);
    
    uint8_t *decoded;
    size_t decoded_len;
    assert(base64_decode(encoded, &decoded, &decoded_len) == 0);
    assert(decoded_len == strlen(test_input));
    assert(memcmp(decoded, test_input, decoded_len) == 0);
    
    printf("✓ Base64 test passed\n");
    
    free(encoded);
    free(decoded);
}

void test_rsa_sign_verify() {
    printf("Testing RSA signing (create test key first)...\n");
    
    // This test requires a test key file
    // In real testing, we would create a temporary key file
    printf("⚠ RSA test skipped (requires test key setup)\n");
}

int main() {
    printf("Running crypto unit tests...\n\n");
    
    test_sha256();
    test_base64();
    test_rsa_sign_verify();
    
    printf("\n✓ All crypto tests completed\n");
    return 0;
}