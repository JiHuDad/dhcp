#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include "dhcp6_vendor.h"

void test_vso_append() {
    printf("Testing VSO sub-option append...\n");
    
    uint8_t buffer[256];
    size_t pos = 0;
    
    // Test appending a simple sub-option
    const char *test_value = "test123";
    assert(vso_append_subopt(buffer, sizeof(buffer), &pos, 71, 
                           (uint8_t*)test_value, strlen(test_value)) == 0);
    
    // Check the encoded data
    assert(pos == 4 + strlen(test_value)); // 2 bytes code + 2 bytes length + value
    
    // Verify code (network byte order)
    uint16_t code = ntohs(*(uint16_t*)buffer);
    assert(code == 71);
    
    // Verify length (network byte order)
    uint16_t length = ntohs(*(uint16_t*)(buffer + 2));
    assert(length == strlen(test_value));
    
    // Verify value
    assert(memcmp(buffer + 4, test_value, strlen(test_value)) == 0);
    
    printf("✓ VSO append test passed\n");
}

void test_vso_buffer_overflow() {
    printf("Testing VSO buffer overflow protection...\n");
    
    uint8_t small_buffer[10];
    size_t pos = 0;
    
    const char *large_value = "this_is_a_very_long_value_that_should_not_fit";
    int result = vso_append_subopt(small_buffer, sizeof(small_buffer), &pos, 
                                  72, (uint8_t*)large_value, strlen(large_value));
    
    // Should fail with buffer overflow
    assert(result < 0);
    
    printf("✓ VSO buffer overflow test passed\n");
}

void test_pem_validation() {
    printf("Testing PEM certificate validation...\n");
    
    const char *valid_pem = 
        "-----BEGIN CERTIFICATE-----\n"
        "MIICljCCAX4CCQDKVaBh8W8+5jANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV\n"
        "-----END CERTIFICATE-----";
    
    const char *invalid_pem = "This is not a PEM certificate";
    
    assert(is_valid_pem_cert(valid_pem) == true);
    assert(is_valid_pem_cert(invalid_pem) == false);
    assert(is_valid_pem_cert(NULL) == false);
    
    printf("✓ PEM validation test passed\n");
}

void test_pem_chain_split() {
    printf("Testing PEM chain splitting...\n");
    
    const char *chain = 
        "-----BEGIN CERTIFICATE-----\n"
        "CERT1DATA\n"
        "-----END CERTIFICATE-----"
        " "
        "-----BEGIN CERTIFICATE-----\n"
        "CERT2DATA\n"
        "-----END CERTIFICATE-----";
    
    char *cert1, *cert2;
    assert(split_pem_chain(chain, &cert1, &cert2) == 0);
    
    assert(cert1 != NULL);
    assert(cert2 != NULL);
    assert(strstr(cert1, "CERT1DATA") != NULL);
    assert(strstr(cert2, "CERT2DATA") != NULL);
    
    free(cert1);
    free(cert2);
    
    printf("✓ PEM chain split test passed\n");
}

int main() {
    printf("Running VSO unit tests...\n\n");
    
    test_vso_append();
    test_vso_buffer_overflow();
    test_pem_validation();
    test_pem_chain_split();
    
    printf("\n✓ All VSO tests completed\n");
    return 0;
}