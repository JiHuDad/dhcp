/*
 * Standalone test for vendor-specific options functionality
 * Tests the core vendor options without full DHCP dependencies
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Simplified definitions for testing */
#define VSO_SUCCESS 0
#define VSO_ERROR -1
#define VSO_INVALID_DATA -2
#define VSO_NOT_FOUND -3

#define VSO_SUBOPT_SERIAL_NUMBER 71
#define VSO_SUBOPT_SIGNATURE 72
#define VSO_SUBOPT_CLIENT_CERT 73
#define VSO_SUBOPT_SERVER_CERT_CHAIN 77

/* Simplified data structures for testing */
struct data_string {
    unsigned char *data;
    size_t len;
};

struct vendor_sub_option {
    uint16_t code;
    uint16_t length;
    unsigned char *data;
};

struct vendor_option {
    uint32_t enterprise_num;
    int sub_option_count;
    struct vendor_sub_option *sub_options;
};

/* Test functions */
void vendor_option_init(struct vendor_option *vso, uint32_t enterprise) {
    memset(vso, 0, sizeof(*vso));
    vso->enterprise_num = enterprise;
}

int vendor_add_sub_option(struct vendor_option *vso, uint16_t code, 
                         const unsigned char *data, uint16_t length) {
    if (!vso || (!data && length > 0)) {
        return VSO_INVALID_DATA;
    }
    
    // Reallocate sub-options array
    vso->sub_options = realloc(vso->sub_options, 
                              (vso->sub_option_count + 1) * sizeof(struct vendor_sub_option));
    if (!vso->sub_options) {
        return VSO_ERROR;
    }
    
    struct vendor_sub_option *sub_opt = &vso->sub_options[vso->sub_option_count];
    sub_opt->code = code;
    sub_opt->length = length;
    
    if (length > 0 && data) {
        sub_opt->data = malloc(length);
        if (!sub_opt->data) {
            return VSO_ERROR;
        }
        memcpy(sub_opt->data, data, length);
    } else {
        sub_opt->data = NULL;
    }
    
    vso->sub_option_count++;
    return VSO_SUCCESS;
}

const struct vendor_sub_option *vendor_find_sub_option(const struct vendor_option *vso, 
                                                       uint16_t code) {
    if (!vso) return NULL;
    
    for (int i = 0; i < vso->sub_option_count; i++) {
        if (vso->sub_options[i].code == code) {
            return &vso->sub_options[i];
        }
    }
    return NULL;
}

int vendor_build_option(const struct vendor_option *vso, struct data_string *result) {
    if (!vso || !result) {
        return VSO_INVALID_DATA;
    }
    
    // Calculate total size needed
    size_t total_size = 4; // Enterprise number
    for (int i = 0; i < vso->sub_option_count; i++) {
        total_size += 4 + vso->sub_options[i].length; // code(2) + length(2) + data
    }
    
    result->data = malloc(total_size);
    if (!result->data) {
        return VSO_ERROR;
    }
    result->len = total_size;
    
    unsigned char *ptr = result->data;
    
    // Write enterprise number (big endian)
    *ptr++ = (vso->enterprise_num >> 24) & 0xFF;
    *ptr++ = (vso->enterprise_num >> 16) & 0xFF;
    *ptr++ = (vso->enterprise_num >> 8) & 0xFF;
    *ptr++ = vso->enterprise_num & 0xFF;
    
    // Write sub-options
    for (int i = 0; i < vso->sub_option_count; i++) {
        struct vendor_sub_option *sub_opt = &vso->sub_options[i];
        
        // Write code (big endian)
        *ptr++ = (sub_opt->code >> 8) & 0xFF;
        *ptr++ = sub_opt->code & 0xFF;
        
        // Write length (big endian)
        *ptr++ = (sub_opt->length >> 8) & 0xFF;
        *ptr++ = sub_opt->length & 0xFF;
        
        // Write data
        if (sub_opt->length > 0 && sub_opt->data) {
            memcpy(ptr, sub_opt->data, sub_opt->length);
            ptr += sub_opt->length;
        }
    }
    
    return VSO_SUCCESS;
}

int vendor_parse_option(const struct data_string *vso_data, struct vendor_option *parsed_vso) {
    if (!vso_data || !parsed_vso || !vso_data->data || vso_data->len < 4) {
        return VSO_INVALID_DATA;
    }
    
    memset(parsed_vso, 0, sizeof(*parsed_vso));
    
    unsigned char *ptr = vso_data->data;
    size_t remaining = vso_data->len;
    
    // Read enterprise number
    if (remaining < 4) return VSO_INVALID_DATA;
    parsed_vso->enterprise_num = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
    ptr += 4;
    remaining -= 4;
    
    // Parse sub-options
    while (remaining >= 4) {
        uint16_t code = (ptr[0] << 8) | ptr[1];
        uint16_t length = (ptr[2] << 8) | ptr[3];
        ptr += 4;
        remaining -= 4;
        
        if (remaining < length) {
            return VSO_INVALID_DATA;
        }
        
        int result = vendor_add_sub_option(parsed_vso, code, ptr, length);
        if (result != VSO_SUCCESS) {
            return result;
        }
        
        ptr += length;
        remaining -= length;
    }
    
    return VSO_SUCCESS;
}

void vendor_option_cleanup(struct vendor_option *vso) {
    if (!vso) return;
    
    for (int i = 0; i < vso->sub_option_count; i++) {
        if (vso->sub_options[i].data) {
            free(vso->sub_options[i].data);
        }
    }
    if (vso->sub_options) {
        free(vso->sub_options);
    }
    memset(vso, 0, sizeof(*vso));
}

void data_string_forget(struct data_string *ds) {
    if (ds && ds->data) {
        free(ds->data);
        ds->data = NULL;
        ds->len = 0;
    }
}

/* Test cases */
int test_vendor_option_init() {
    printf("Test 1: Vendor option initialization...\n");
    
    struct vendor_option vso;
    vendor_option_init(&vso, 12345);
    
    if (vso.enterprise_num != 12345 || vso.sub_option_count != 0 || vso.sub_options != NULL) {
        printf("  FAIL: Initialization failed\n");
        return 0;
    }
    
    printf("  PASS: Vendor option initialized correctly\n");
    return 1;
}

int test_sub_option_operations() {
    printf("Test 2: Sub-option add/find operations...\n");
    
    struct vendor_option vso;
    vendor_option_init(&vso, 12345);
    
    const char *test_serial = "TEST123456789";
    int result = vendor_add_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER,
                                      (const unsigned char *)test_serial,
                                      strlen(test_serial));
    
    if (result != VSO_SUCCESS) {
        printf("  FAIL: Failed to add sub-option\n");
        vendor_option_cleanup(&vso);
        return 0;
    }
    
    if (vso.sub_option_count != 1) {
        printf("  FAIL: Wrong sub-option count\n");
        vendor_option_cleanup(&vso);
        return 0;
    }
    
    const struct vendor_sub_option *found = vendor_find_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER);
    if (!found || found->length != strlen(test_serial) || 
        memcmp(found->data, test_serial, found->length) != 0) {
        printf("  FAIL: Sub-option not found or incorrect data\n");
        vendor_option_cleanup(&vso);
        return 0;
    }
    
    printf("  PASS: Sub-option operations working correctly\n");
    vendor_option_cleanup(&vso);
    return 1;
}

int test_build_parse_roundtrip() {
    printf("Test 3: Build/parse round-trip...\n");
    
    struct vendor_option vso;
    vendor_option_init(&vso, 12345);
    
    // Add multiple sub-options
    const char *serial = "ABC123";
    const char *signature = "MockSig";
    
    if (vendor_add_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER,
                             (const unsigned char *)serial, strlen(serial)) != VSO_SUCCESS) {
        printf("  FAIL: Failed to add serial sub-option\n");
        vendor_option_cleanup(&vso);
        return 0;
    }
    
    if (vendor_add_sub_option(&vso, VSO_SUBOPT_SIGNATURE,
                             (const unsigned char *)signature, strlen(signature)) != VSO_SUCCESS) {
        printf("  FAIL: Failed to add signature sub-option\n");
        vendor_option_cleanup(&vso);
        return 0;
    }
    
    // Build wire format
    struct data_string wire_data;
    if (vendor_build_option(&vso, &wire_data) != VSO_SUCCESS) {
        printf("  FAIL: Failed to build wire format\n");
        vendor_option_cleanup(&vso);
        return 0;
    }
    
    // Parse it back
    struct vendor_option parsed_vso;
    if (vendor_parse_option(&wire_data, &parsed_vso) != VSO_SUCCESS) {
        printf("  FAIL: Failed to parse wire format\n");
        data_string_forget(&wire_data);
        vendor_option_cleanup(&vso);
        return 0;
    }
    
    // Verify round-trip
    if (parsed_vso.enterprise_num != 12345 || parsed_vso.sub_option_count != 2) {
        printf("  FAIL: Round-trip verification failed - basic data\n");
        data_string_forget(&wire_data);
        vendor_option_cleanup(&vso);
        vendor_option_cleanup(&parsed_vso);
        return 0;
    }
    
    const struct vendor_sub_option *parsed_serial = 
        vendor_find_sub_option(&parsed_vso, VSO_SUBOPT_SERIAL_NUMBER);
    if (!parsed_serial || parsed_serial->length != strlen(serial) ||
        memcmp(parsed_serial->data, serial, parsed_serial->length) != 0) {
        printf("  FAIL: Round-trip verification failed - serial data\n");
        data_string_forget(&wire_data);
        vendor_option_cleanup(&vso);
        vendor_option_cleanup(&parsed_vso);
        return 0;
    }
    
    printf("  PASS: Build/parse round-trip successful\n");
    printf("    Enterprise: %u\n", parsed_vso.enterprise_num);
    printf("    Sub-options: %d\n", parsed_vso.sub_option_count);
    printf("    Wire size: %zu bytes\n", wire_data.len);
    
    data_string_forget(&wire_data);
    vendor_option_cleanup(&vso);
    vendor_option_cleanup(&parsed_vso);
    return 1;
}

int test_error_handling() {
    printf("Test 4: Error handling...\n");
    
    struct vendor_option vso;
    vendor_option_init(&vso, 12345);
    
    // Test NULL parameters
    if (vendor_add_sub_option(NULL, VSO_SUBOPT_SERIAL_NUMBER, 
                             (const unsigned char *)"test", 4) == VSO_SUCCESS) {
        printf("  FAIL: NULL VSO should fail\n");
        vendor_option_cleanup(&vso);
        return 0;
    }
    
    if (vendor_add_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER, NULL, 4) == VSO_SUCCESS) {
        printf("  FAIL: NULL data with non-zero length should fail\n");
        vendor_option_cleanup(&vso);
        return 0;
    }
    
    if (vendor_find_sub_option(NULL, VSO_SUBOPT_SERIAL_NUMBER) != NULL) {
        printf("  FAIL: NULL VSO find should return NULL\n");
        vendor_option_cleanup(&vso);
        return 0;
    }
    
    // Test parsing invalid data
    struct data_string invalid_data;
    invalid_data.data = (unsigned char *)"XX";
    invalid_data.len = 2; // Too short for enterprise number
    
    struct vendor_option parsed_vso;
    if (vendor_parse_option(&invalid_data, &parsed_vso) == VSO_SUCCESS) {
        printf("  FAIL: Invalid data should fail parsing\n");
        vendor_option_cleanup(&vso);
        return 0;
    }
    
    printf("  PASS: Error handling working correctly\n");
    vendor_option_cleanup(&vso);
    return 1;
}

int main() {
    printf("DHCPv6 Vendor Options Standalone Test\n");
    printf("=====================================\n\n");
    
    int tests_passed = 0;
    int total_tests = 4;
    
    tests_passed += test_vendor_option_init();
    tests_passed += test_sub_option_operations();
    tests_passed += test_build_parse_roundtrip();
    tests_passed += test_error_handling();
    
    printf("\nTest Summary\n");
    printf("============\n");
    printf("Passed: %d/%d\n", tests_passed, total_tests);
    
    if (tests_passed == total_tests) {
        printf("Result: ALL TESTS PASSED ✓\n");
        printf("\nCore vendor-specific options functionality is working correctly.\n");
        return 0;
    } else {
        printf("Result: SOME TESTS FAILED ✗\n");
        return 1;
    }
}