/*
 * Copyright (C) 2024 Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Unit tests for vendor_options functionality
 */

#include "config.h"
#include "dhcpd.h"
#include "vendor_options.h"

#include <atf-c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test initialization */
ATF_TC(vendor_options_init_test);
ATF_TC_HEAD(vendor_options_init_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test vendor_options_init function");
}
ATF_TC_BODY(vendor_options_init_test, tc) {
    int result;
    
    /* Test successful initialization */
    result = vendor_options_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Test re-initialization (should succeed) */
    result = vendor_options_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Cleanup */
    vendor_options_cleanup();
}

/* Test VSO structure initialization */
ATF_TC(vendor_option_init_test);
ATF_TC_HEAD(vendor_option_init_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test vendor_option structure initialization");
}
ATF_TC_BODY(vendor_option_init_test, tc) {
    struct vendor_option vso;
    int result;
    
    /* Initialize vendor options */
    result = vendor_options_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Test VSO initialization */
    memset(&vso, 0xFF, sizeof(vso)); /* Fill with garbage */
    vendor_option_init(&vso, 12345);
    
    ATF_CHECK_EQ(vso.enterprise_num, 12345);
    ATF_CHECK_EQ(vso.sub_option_count, 0);
    ATF_CHECK(vso.sub_options == NULL);
    
    /* Cleanup */
    vendor_option_cleanup(&vso);
    vendor_options_cleanup();
}

/* Test sub-option operations */
ATF_TC(sub_option_test);
ATF_TC_HEAD(sub_option_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test sub-option add/find operations");
}
ATF_TC_BODY(sub_option_test, tc) {
    struct vendor_option vso;
    const struct vendor_sub_option *found;
    int result;
    const char *test_data = "TestSerialNumber";
    
    /* Initialize */
    result = vendor_options_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    vendor_option_init(&vso, 12345);
    
    /* Test adding sub-option */
    result = vendor_add_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER,
                                  (const unsigned char *)test_data,
                                  strlen(test_data));
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    ATF_CHECK_EQ(vso.sub_option_count, 1);
    
    /* Test finding sub-option */
    found = vendor_find_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER);
    ATF_REQUIRE(found != NULL);
    ATF_CHECK_EQ(found->code, VSO_SUBOPT_SERIAL_NUMBER);
    ATF_CHECK_EQ(found->length, strlen(test_data));
    ATF_CHECK(memcmp(found->data, test_data, found->length) == 0);
    
    /* Test finding non-existent sub-option */
    found = vendor_find_sub_option(&vso, VSO_SUBOPT_SERVER_CERT_CHAIN);
    ATF_CHECK(found == NULL);
    
    /* Add another sub-option */
    const char *sig_data = "TestSignature";
    result = vendor_add_sub_option(&vso, VSO_SUBOPT_SIGNATURE,
                                  (const unsigned char *)sig_data,
                                  strlen(sig_data));
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    ATF_CHECK_EQ(vso.sub_option_count, 2);
    
    /* Verify both sub-options exist */
    found = vendor_find_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER);
    ATF_CHECK(found != NULL);
    found = vendor_find_sub_option(&vso, VSO_SUBOPT_SIGNATURE);
    ATF_CHECK(found != NULL);
    
    /* Cleanup */
    vendor_option_cleanup(&vso);
    vendor_options_cleanup();
}

ATF_TC(sub_option_edge_cases);
ATF_TC_HEAD(sub_option_edge_cases, tc) {
    atf_tc_set_md_var(tc, "descr", "Test sub-option edge cases and error handling");
}
ATF_TC_BODY(sub_option_edge_cases, tc) {
    struct vendor_option vso;
    int result;
    
    /* Initialize */
    result = vendor_options_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    vendor_option_init(&vso, 12345);
    
    /* Test adding with NULL VSO */
    result = vendor_add_sub_option(NULL, VSO_SUBOPT_SERIAL_NUMBER,
                                  (const unsigned char *)"test", 4);
    ATF_CHECK(result != VSO_SUCCESS);
    
    /* Test adding with NULL data */
    result = vendor_add_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER, NULL, 4);
    ATF_CHECK(result != VSO_SUCCESS);
    
    /* Test adding with zero length but non-NULL data */
    result = vendor_add_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER,
                                  (const unsigned char *)"test", 0);
    ATF_CHECK(result == VSO_SUCCESS);
    
    /* Test finding with NULL VSO */
    const struct vendor_sub_option *found = vendor_find_sub_option(NULL, VSO_SUBOPT_SERIAL_NUMBER);
    ATF_CHECK(found == NULL);
    
    /* Test adding maximum data size */
    unsigned char large_data[65535];
    memset(large_data, 'A', sizeof(large_data));
    result = vendor_add_sub_option(&vso, VSO_SUBOPT_CLIENT_CERT, large_data, sizeof(large_data));
    ATF_CHECK(result == VSO_SUCCESS);
    
    /* Cleanup */
    vendor_option_cleanup(&vso);
    vendor_options_cleanup();
}

/* Test VSO parsing */
ATF_TC(vso_parse_test);
ATF_TC_HEAD(vso_parse_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test VSO parsing from wire format");
}
ATF_TC_BODY(vso_parse_test, tc) {
    struct vendor_option vso;
    struct data_string wire_data;
    int result;
    
    /* Create test VSO wire format:
     * Enterprise Number: 12345 (0x00003039)
     * Sub-option 71, length 4, data "TEST"
     */
    unsigned char test_wire[] = {
        0x00, 0x00, 0x30, 0x39,  /* Enterprise number 12345 */
        0x00, 0x47,              /* Sub-option code 71 */
        0x00, 0x04,              /* Length 4 */
        'T', 'E', 'S', 'T'       /* Data "TEST" */
    };
    
    /* Initialize */
    result = vendor_options_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Set up wire data */
    wire_data.data = test_wire;
    wire_data.len = sizeof(test_wire);
    
    /* Parse VSO */
    result = vendor_parse_option(&wire_data, &vso);
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Verify parsed data */
    ATF_CHECK_EQ(vso.enterprise_num, 12345);
    ATF_CHECK_EQ(vso.sub_option_count, 1);
    
    const struct vendor_sub_option *sub_opt = vendor_find_sub_option(&vso, 71);
    ATF_REQUIRE(sub_opt != NULL);
    ATF_CHECK_EQ(sub_opt->code, 71);
    ATF_CHECK_EQ(sub_opt->length, 4);
    ATF_CHECK(memcmp(sub_opt->data, "TEST", 4) == 0);
    
    /* Cleanup */
    vendor_option_cleanup(&vso);
    vendor_options_cleanup();
}

ATF_TC(vso_parse_errors);
ATF_TC_HEAD(vso_parse_errors, tc) {
    atf_tc_set_md_var(tc, "descr", "Test VSO parsing error handling");
}
ATF_TC_BODY(vso_parse_errors, tc) {
    struct vendor_option vso;
    struct data_string wire_data;
    int result;
    
    /* Initialize */
    result = vendor_options_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Test NULL parameters */
    result = vendor_parse_option(NULL, &vso);
    ATF_CHECK(result != VSO_SUCCESS);
    
    result = vendor_parse_option(&wire_data, NULL);
    ATF_CHECK(result != VSO_SUCCESS);
    
    /* Test insufficient data for enterprise number */
    unsigned char short_data[] = { 0x00, 0x00 };
    wire_data.data = short_data;
    wire_data.len = sizeof(short_data);
    result = vendor_parse_option(&wire_data, &vso);
    ATF_CHECK(result != VSO_SUCCESS);
    
    /* Test truncated sub-option */
    unsigned char truncated_data[] = {
        0x00, 0x00, 0x30, 0x39,  /* Enterprise number */
        0x00, 0x47,              /* Sub-option code */
        0x00, 0x04,              /* Length 4 */
        'T', 'E'                 /* Only 2 bytes of data */
    };
    wire_data.data = truncated_data;
    wire_data.len = sizeof(truncated_data);
    result = vendor_parse_option(&wire_data, &vso);
    ATF_CHECK(result != VSO_SUCCESS);
    
    vendor_options_cleanup();
}

/* Test VSO building */
ATF_TC(vso_build_test);
ATF_TC_HEAD(vso_build_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test VSO building to wire format");
}
ATF_TC_BODY(vso_build_test, tc) {
    struct vendor_option vso;
    struct data_string result_data;
    int result;
    const char *test_serial = "ABC123";
    
    /* Initialize */
    result = vendor_options_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    vendor_option_init(&vso, 12345);
    
    /* Add sub-option */
    result = vendor_add_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER,
                                  (const unsigned char *)test_serial,
                                  strlen(test_serial));
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Build wire format */
    memset(&result_data, 0, sizeof(result_data));
    result = vendor_build_option(&vso, &result_data);
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    ATF_REQUIRE(result_data.data != NULL);
    ATF_REQUIRE(result_data.len > 0);
    
    /* Verify wire format structure */
    ATF_REQUIRE(result_data.len >= 4); /* At least enterprise number */
    
    /* Check enterprise number (first 4 bytes, big endian) */
    uint32_t enterprise = (result_data.data[0] << 24) |
                         (result_data.data[1] << 16) |
                         (result_data.data[2] << 8) |
                         result_data.data[3];
    ATF_CHECK_EQ(enterprise, 12345);
    
    /* Parse it back to verify */
    struct vendor_option parsed_vso;
    int parse_result = vendor_parse_option(&result_data, &parsed_vso);
    ATF_CHECK_EQ(parse_result, VSO_SUCCESS);
    ATF_CHECK_EQ(parsed_vso.enterprise_num, 12345);
    ATF_CHECK_EQ(parsed_vso.sub_option_count, 1);
    
    /* Cleanup */
    data_string_forget(&result_data, MDL);
    vendor_option_cleanup(&vso);
    vendor_option_cleanup(&parsed_vso);
    vendor_options_cleanup();
}

/* Test error string functions */
ATF_TC(error_string_test);
ATF_TC_HEAD(error_string_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test vendor error string functions");
}
ATF_TC_BODY(error_string_test, tc) {
    const char *error_str;
    
    /* Test known error codes */
    error_str = vendor_get_error_string(VSO_SUCCESS);
    ATF_CHECK(error_str != NULL);
    ATF_CHECK(strlen(error_str) > 0);
    
    error_str = vendor_get_error_string(VSO_ERROR);
    ATF_CHECK(error_str != NULL);
    ATF_CHECK(strlen(error_str) > 0);
    
    error_str = vendor_get_error_string(VSO_INVALID_DATA);
    ATF_CHECK(error_str != NULL);
    ATF_CHECK(strlen(error_str) > 0);
    
    error_str = vendor_get_error_string(VSO_NOT_FOUND);
    ATF_CHECK(error_str != NULL);
    ATF_CHECK(strlen(error_str) > 0);
    
    /* Test unknown error code */
    error_str = vendor_get_error_string(999);
    ATF_CHECK(error_str != NULL);
    ATF_CHECK(strlen(error_str) > 0);
}

/* Test signature creation */
ATF_TC(signature_creation_test);
ATF_TC_HEAD(signature_creation_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test vendor signature creation");
}
ATF_TC_BODY(signature_creation_test, tc) {
    struct data_string signature;
    int result;
    const char *test_data = "TestData";
    
    /* Initialize */
    result = vendor_options_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Test signature creation with non-existent key file */
    memset(&signature, 0, sizeof(signature));
    result = vendor_create_signature(test_data, "/nonexistent/key.pem", &signature);
    /* This should fail gracefully */
    ATF_CHECK(result != VSO_SUCCESS);
    
    /* Test with NULL parameters */
    result = vendor_create_signature(NULL, "/tmp/key.pem", &signature);
    ATF_CHECK(result != VSO_SUCCESS);
    
    result = vendor_create_signature(test_data, NULL, &signature);
    ATF_CHECK(result != VSO_SUCCESS);
    
    result = vendor_create_signature(test_data, "/tmp/key.pem", NULL);
    ATF_CHECK(result != VSO_SUCCESS);
    
    vendor_options_cleanup();
}

/* Test certificate chain splitting */
ATF_TC(cert_chain_test);
ATF_TC_HEAD(cert_chain_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test certificate chain splitting");
}
ATF_TC_BODY(cert_chain_test, tc) {
    struct data_string chain, cert1, cert2;
    int result;
    const char *test_chain = 
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBkTCB+wIJAL7LCvp1aBSNMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBFRl\n"
        "-----END CERTIFICATE-----\n"
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBkTCB+wIJAL7LCvp1aBSNMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBFRl\n"
        "-----END CERTIFICATE-----\n";
    
    /* Initialize */
    result = vendor_options_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Set up chain data */
    chain.data = (unsigned char *)test_chain;
    chain.len = strlen(test_chain);
    
    memset(&cert1, 0, sizeof(cert1));
    memset(&cert2, 0, sizeof(cert2));
    
    /* Test certificate splitting */
    result = vendor_split_certificate_chain(&chain, &cert1, &cert2);
    ATF_CHECK(result == VSO_SUCCESS);
    
    /* Verify results */
    if (result == VSO_SUCCESS) {
        ATF_CHECK(cert1.data != NULL);
        ATF_CHECK(cert1.len > 0);
        ATF_CHECK(cert2.data != NULL);
        ATF_CHECK(cert2.len > 0);
        
        /* Clean up allocated memory */
        if (cert1.data) data_string_forget(&cert1, MDL);
        if (cert2.data) data_string_forget(&cert2, MDL);
    }
    
    /* Test with single certificate */
    const char *single_cert = 
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBkTCB+wIJAL7LCvp1aBSNMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBFRl\n"
        "-----END CERTIFICATE-----\n";
    
    chain.data = (unsigned char *)single_cert;
    chain.len = strlen(single_cert);
    
    memset(&cert1, 0, sizeof(cert1));
    memset(&cert2, 0, sizeof(cert2));
    
    result = vendor_split_certificate_chain(&chain, &cert1, &cert2);
    /* Single cert should still work but cert2 might be empty */
    
    if (cert1.data) data_string_forget(&cert1, MDL);
    if (cert2.data) data_string_forget(&cert2, MDL);
    
    vendor_options_cleanup();
}

/* Main test suite */
ATF_TP_ADD_TCS(tp) {
    ATF_TP_ADD_TC(tp, vendor_options_init_test);
    ATF_TP_ADD_TC(tp, vendor_option_init_test);
    ATF_TP_ADD_TC(tp, sub_option_test);
    ATF_TP_ADD_TC(tp, sub_option_edge_cases);
    ATF_TP_ADD_TC(tp, vso_parse_test);
    ATF_TP_ADD_TC(tp, vso_parse_errors);
    ATF_TP_ADD_TC(tp, vso_build_test);
    ATF_TP_ADD_TC(tp, error_string_test);
    ATF_TP_ADD_TC(tp, signature_creation_test);
    ATF_TP_ADD_TC(tp, cert_chain_test);
    
    return atf_no_error();
}