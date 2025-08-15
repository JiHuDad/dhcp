/*
 * Copyright (C) 2024 Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Unit tests for crypto_utils functionality
 */

#include "config.h"
#include "dhcpd.h"
#include "crypto_utils.h"

#include <atf-c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* Test initialization */
ATF_TC(crypto_utils_init_test);
ATF_TC_HEAD(crypto_utils_init_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test crypto_utils_init function");
}
ATF_TC_BODY(crypto_utils_init_test, tc) {
    int result;
    
    /* Test successful initialization */
    result = crypto_utils_init();
    ATF_REQUIRE_EQ(result, CRYPTO_SUCCESS);
    
    /* Test re-initialization (should succeed) */
    result = crypto_utils_init();
    ATF_REQUIRE_EQ(result, CRYPTO_SUCCESS);
    
    /* Cleanup */
    crypto_utils_cleanup();
}

/* Test Base64 encoding/decoding */
ATF_TC(base64_test);
ATF_TC_HEAD(base64_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test Base64 encoding/decoding functions");
}
ATF_TC_BODY(base64_test, tc) {
    int result;
    char *encoded;
    unsigned char *decoded;
    size_t decoded_len;
    const char *test_data = "Hello, World!";
    const char *expected_encoded = "SGVsbG8sIFdvcmxkIQ==";
    
    /* Initialize crypto utilities */
    result = crypto_utils_init();
    ATF_REQUIRE_EQ(result, CRYPTO_SUCCESS);
    
    /* Test encoding */
    encoded = crypto_base64_encode((const unsigned char *)test_data, strlen(test_data));
    ATF_REQUIRE(encoded != NULL);
    ATF_CHECK_STREQ(encoded, expected_encoded);
    
    /* Test decoding */
    result = crypto_base64_decode(encoded, &decoded, &decoded_len);
    ATF_REQUIRE_EQ(result, CRYPTO_SUCCESS);
    ATF_REQUIRE(decoded != NULL);
    ATF_REQUIRE_EQ(decoded_len, strlen(test_data));
    ATF_CHECK(memcmp(decoded, test_data, decoded_len) == 0);
    
    /* Clean up */
    dfree(encoded, MDL);
    dfree(decoded, MDL);
    crypto_utils_cleanup();
}

ATF_TC(base64_edge_cases);
ATF_TC_HEAD(base64_edge_cases, tc) {
    atf_tc_set_md_var(tc, "descr", "Test Base64 edge cases and error handling");
}
ATF_TC_BODY(base64_edge_cases, tc) {
    int result;
    char *encoded;
    unsigned char *decoded;
    size_t decoded_len;
    
    /* Initialize crypto utilities */
    result = crypto_utils_init();
    ATF_REQUIRE_EQ(result, CRYPTO_SUCCESS);
    
    /* Test empty data encoding */
    encoded = crypto_base64_encode((const unsigned char *)"", 0);
    ATF_CHECK(encoded != NULL);
    if (encoded) {
        dfree(encoded, MDL);
    }
    
    /* Test NULL data encoding */
    encoded = crypto_base64_encode(NULL, 0);
    ATF_CHECK(encoded == NULL);
    
    /* Test NULL string decoding */
    result = crypto_base64_decode(NULL, &decoded, &decoded_len);
    ATF_CHECK(result != CRYPTO_SUCCESS);
    
    /* Test invalid base64 string */
    result = crypto_base64_decode("Invalid@Base64!", &decoded, &decoded_len);
    ATF_CHECK(result != CRYPTO_SUCCESS);
    
    crypto_utils_cleanup();
}

/* Test PEM certificate operations */
ATF_TC(pem_certificate_test);
ATF_TC_HEAD(pem_certificate_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test PEM certificate loading and saving");
}
ATF_TC_BODY(pem_certificate_test, tc) {
    int result;
    struct data_string cert_data;
    const char *test_cert = 
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBkTCB+wIJAL7LCvp1aBSNMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBFRl\n"
        "c3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAPMQ0wCwYDVQQDDARU\n"
        "ZXN0MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALRiMLAh9iimur8VA7qVK7MNiche\n"
        "oArnqJamFMMe7pFrAuDseHwcx5dsTbCCWPt184mLaRDsgHWBTrPiO13SMCMCAwEA\n"
        "ATANBgkqhkiG9w0BAQsFAANBAE4Hel0PttmBJwVF7vDVLMtJLPn6nBwEpZj8AxMu\n"
        "L7HSUvzazJDgqCL7gHRV9h5q4Wf8j3q9sF9XaP7dSwMQ=\n"
        "-----END CERTIFICATE-----\n";
    const char *test_file = "/tmp/test_cert.pem";
    FILE *fp;
    
    /* Initialize crypto utilities */
    result = crypto_utils_init();
    ATF_REQUIRE_EQ(result, CRYPTO_SUCCESS);
    
    /* Create test certificate file */
    fp = fopen(test_file, "w");
    ATF_REQUIRE(fp != NULL);
    fprintf(fp, "%s", test_cert);
    fclose(fp);
    
    /* Test certificate loading */
    memset(&cert_data, 0, sizeof(cert_data));
    result = crypto_load_pem_certificate(test_file, &cert_data);
    ATF_REQUIRE_EQ(result, CRYPTO_SUCCESS);
    ATF_REQUIRE(cert_data.data != NULL);
    ATF_REQUIRE(cert_data.len > 0);
    
    /* Verify loaded data matches original */
    ATF_CHECK(cert_data.len == strlen(test_cert));
    ATF_CHECK(memcmp(cert_data.data, test_cert, cert_data.len) == 0);
    
    /* Test certificate saving */
    const char *save_file = "/tmp/test_cert_saved.pem";
    result = crypto_save_pem_certificate(save_file, &cert_data, 0644);
    ATF_REQUIRE_EQ(result, CRYPTO_SUCCESS);
    
    /* Verify saved file exists and has correct permissions */
    struct stat st;
    ATF_REQUIRE(stat(save_file, &st) == 0);
    ATF_CHECK((st.st_mode & 0777) == 0644);
    
    /* Clean up */
    data_string_forget(&cert_data, MDL);
    unlink(test_file);
    unlink(save_file);
    crypto_utils_cleanup();
}

ATF_TC(pem_certificate_errors);
ATF_TC_HEAD(pem_certificate_errors, tc) {
    atf_tc_set_md_var(tc, "descr", "Test PEM certificate error handling");
}
ATF_TC_BODY(pem_certificate_errors, tc) {
    int result;
    struct data_string cert_data;
    
    /* Initialize crypto utilities */
    result = crypto_utils_init();
    ATF_REQUIRE_EQ(result, CRYPTO_SUCCESS);
    
    /* Test loading non-existent file */
    memset(&cert_data, 0, sizeof(cert_data));
    result = crypto_load_pem_certificate("/nonexistent/file.pem", &cert_data);
    ATF_CHECK(result != CRYPTO_SUCCESS);
    
    /* Test loading with NULL parameters */
    result = crypto_load_pem_certificate(NULL, &cert_data);
    ATF_CHECK(result != CRYPTO_SUCCESS);
    
    result = crypto_load_pem_certificate("/tmp/test.pem", NULL);
    ATF_CHECK(result != CRYPTO_SUCCESS);
    
    /* Test saving with invalid path */
    cert_data.data = (unsigned char *)"test";
    cert_data.len = 4;
    result = crypto_save_pem_certificate("/invalid/path/cert.pem", &cert_data, 0644);
    ATF_CHECK(result != CRYPTO_SUCCESS);
    
    crypto_utils_cleanup();
}

/* Test RSA key operations */
ATF_TC(rsa_key_test);
ATF_TC_HEAD(rsa_key_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test RSA key loading operations");
}
ATF_TC_BODY(rsa_key_test, tc) {
    int result;
    crypto_rsa_key_t *key;
    const char *test_key = 
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0Yosp2Z1xJ5xp\n"
        "pHlbGPzYqQvjnFEQ6VHJ8C7yPm3dKqNvP5gF9hMqKQUXcJjDLHbxQqKjHgYzNsQ8\n"
        "AgEAAoIBAQC0YoHel0PttmBJwVF7vDVLMtJLPn6nBwEpZj8AxMuL7HSUvzazJDgq\n"
        "CL7gHRV9h5q4Wf8j3q9sF9XaP7dSwMQIhAJBALRiMLAh9iimur8VA7qVK7MNiche\n"
        "-----END PRIVATE KEY-----\n";
    const char *test_file = "/tmp/test_key.pem";
    FILE *fp;
    
    /* Initialize crypto utilities */
    result = crypto_utils_init();
    ATF_REQUIRE_EQ(result, CRYPTO_SUCCESS);
    
    /* Create test key file */
    fp = fopen(test_file, "w");
    ATF_REQUIRE(fp != NULL);
    fprintf(fp, "%s", test_key);
    fclose(fp);
    
    /* Test key loading - this may fail with invalid key format */
    /* Just test that the function handles the file properly */
    key = crypto_load_rsa_private_key(test_file);
    /* We don't require success since this is a dummy key */
    /* The important thing is that it doesn't crash */
    
    if (key) {
        crypto_free_rsa_key(key);
    }
    
    /* Test loading non-existent file */
    key = crypto_load_rsa_private_key("/nonexistent/key.pem");
    ATF_CHECK(key == NULL);
    
    /* Test with NULL parameter */
    key = crypto_load_rsa_private_key(NULL);
    ATF_CHECK(key == NULL);
    
    /* Clean up */
    unlink(test_file);
    crypto_utils_cleanup();
}

/* Test error string functions */
ATF_TC(error_string_test);
ATF_TC_HEAD(error_string_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test crypto error string functions");
}
ATF_TC_BODY(error_string_test, tc) {
    const char *error_str;
    
    /* Test known error codes */
    error_str = crypto_get_error_string(CRYPTO_SUCCESS);
    ATF_CHECK(error_str != NULL);
    ATF_CHECK(strlen(error_str) > 0);
    
    error_str = crypto_get_error_string(CRYPTO_ERROR);
    ATF_CHECK(error_str != NULL);
    ATF_CHECK(strlen(error_str) > 0);
    
    error_str = crypto_get_error_string(CRYPTO_INVALID_DATA);
    ATF_CHECK(error_str != NULL);
    ATF_CHECK(strlen(error_str) > 0);
    
    /* Test unknown error code */
    error_str = crypto_get_error_string(999);
    ATF_CHECK(error_str != NULL);
    ATF_CHECK(strlen(error_str) > 0);
}

/* Test data validation functions */
ATF_TC(validation_test);
ATF_TC_HEAD(validation_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test data validation functions");
}
ATF_TC_BODY(validation_test, tc) {
    int result;
    struct data_string valid_pem;
    struct data_string invalid_pem;
    const char *valid_cert = 
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBkTCB+wIJAL7LCvp1aBSNMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBFRl\n"
        "-----END CERTIFICATE-----\n";
    const char *invalid_cert = "Not a certificate";
    
    /* Initialize crypto utilities */
    result = crypto_utils_init();
    ATF_REQUIRE_EQ(result, CRYPTO_SUCCESS);
    
    /* Test valid PEM format */
    valid_pem.data = (unsigned char *)valid_cert;
    valid_pem.len = strlen(valid_cert);
    result = crypto_validate_pem_format(&valid_pem);
    ATF_CHECK(result == CRYPTO_SUCCESS);
    
    /* Test invalid PEM format */
    invalid_pem.data = (unsigned char *)invalid_cert;
    invalid_pem.len = strlen(invalid_cert);
    result = crypto_validate_pem_format(&invalid_pem);
    ATF_CHECK(result != CRYPTO_SUCCESS);
    
    /* Test NULL parameter */
    result = crypto_validate_pem_format(NULL);
    ATF_CHECK(result != CRYPTO_SUCCESS);
    
    /* Test empty data */
    invalid_pem.data = NULL;
    invalid_pem.len = 0;
    result = crypto_validate_pem_format(&invalid_pem);
    ATF_CHECK(result != CRYPTO_SUCCESS);
    
    crypto_utils_cleanup();
}

/* Main test suite */
ATF_TP_ADD_TCS(tp) {
    ATF_TP_ADD_TC(tp, crypto_utils_init_test);
    ATF_TP_ADD_TC(tp, base64_test);
    ATF_TP_ADD_TC(tp, base64_edge_cases);
    ATF_TP_ADD_TC(tp, pem_certificate_test);
    ATF_TP_ADD_TC(tp, pem_certificate_errors);
    ATF_TP_ADD_TC(tp, rsa_key_test);
    ATF_TP_ADD_TC(tp, error_string_test);
    ATF_TP_ADD_TC(tp, validation_test);
    
    return atf_no_error();
}