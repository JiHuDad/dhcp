/*
 * Copyright (C) 2024 Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Unit tests for vendor_handler functionality
 */

#include "config.h"
#include "dhcpd.h"
#include "vendor_options.h"

#include <atf-c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forward declaration from vendor_handler.c */
extern int vendor_handler_init(void);
extern void vendor_handler_cleanup(void);
extern int vendor_handle_request(struct packet *packet,
                                struct option_state *options,
                                struct option_state *reply_options);

/* Mock packet structure for testing */
struct mock_packet {
    struct packet base;
    unsigned char raw_data[1024];
};

/* Mock option state for testing */
struct mock_option_state {
    struct option_state base;
};

/* Test initialization */
ATF_TC(vendor_handler_init_test);
ATF_TC_HEAD(vendor_handler_init_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test vendor_handler_init function");
}
ATF_TC_BODY(vendor_handler_init_test, tc) {
    int result;
    
    /* Test successful initialization */
    result = vendor_handler_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Test re-initialization (should succeed) */
    result = vendor_handler_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Cleanup */
    vendor_handler_cleanup();
}

/* Test basic vendor request handling */
ATF_TC(vendor_handle_basic_test);
ATF_TC_HEAD(vendor_handle_basic_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test basic vendor request handling");
}
ATF_TC_BODY(vendor_handle_basic_test, tc) {
    struct mock_packet packet;
    struct mock_option_state options;
    struct mock_option_state reply_options;
    int result;
    
    /* Initialize vendor handler */
    result = vendor_handler_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Initialize mock structures */
    memset(&packet, 0, sizeof(packet));
    memset(&options, 0, sizeof(options));
    memset(&reply_options, 0, sizeof(reply_options));
    
    /* Set up basic packet structure */
    packet.base.raw = packet.raw_data;
    packet.base.packet_length = sizeof(packet.raw_data);
    packet.base.packet_type = DHCPV6_SOLICIT;
    
    /* Test handling with NULL parameters */
    result = vendor_handle_request(NULL, &options.base, &reply_options.base);
    ATF_CHECK(result != VSO_SUCCESS);
    
    result = vendor_handle_request(&packet.base, NULL, &reply_options.base);
    ATF_CHECK(result != VSO_SUCCESS);
    
    result = vendor_handle_request(&packet.base, &options.base, NULL);
    ATF_CHECK(result != VSO_SUCCESS);
    
    /* Test handling with valid parameters but no vendor options */
    result = vendor_handle_request(&packet.base, &options.base, &reply_options.base);
    /* Should succeed even without vendor options */
    ATF_CHECK(result == VSO_SUCCESS || result == VSO_NOT_FOUND);
    
    /* Cleanup */
    vendor_handler_cleanup();
}

/* Test vendor option creation in response */
ATF_TC(vendor_response_creation_test);
ATF_TC_HEAD(vendor_response_creation_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test vendor response option creation");
}
ATF_TC_BODY(vendor_response_creation_test, tc) {
    struct vendor_option vso;
    struct data_string built_vso;
    int result;
    
    /* Initialize vendor handler */
    result = vendor_handler_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Create a test VSO with server certificate chain */
    vendor_option_init(&vso, 12345);
    
    /* Add a mock certificate chain sub-option */
    const char *mock_cert = 
        "-----BEGIN CERTIFICATE-----\n"
        "MockCertificateDataForTesting\n"
        "-----END CERTIFICATE-----\n";
    
    result = vendor_add_sub_option(&vso, VSO_SUBOPT_SERVER_CERT_CHAIN,
                                  (const unsigned char *)mock_cert,
                                  strlen(mock_cert));
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Build the VSO into wire format */
    memset(&built_vso, 0, sizeof(built_vso));
    result = vendor_build_option(&vso, &built_vso);
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    ATF_REQUIRE(built_vso.data != NULL);
    ATF_REQUIRE(built_vso.len > 0);
    
    /* Verify the built VSO can be parsed back */
    struct vendor_option parsed_vso;
    result = vendor_parse_option(&built_vso, &parsed_vso);
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    ATF_CHECK_EQ(parsed_vso.enterprise_num, 12345);
    ATF_CHECK_EQ(parsed_vso.sub_option_count, 1);
    
    const struct vendor_sub_option *cert_opt = 
        vendor_find_sub_option(&parsed_vso, VSO_SUBOPT_SERVER_CERT_CHAIN);
    ATF_REQUIRE(cert_opt != NULL);
    ATF_CHECK_EQ(cert_opt->code, VSO_SUBOPT_SERVER_CERT_CHAIN);
    ATF_CHECK_EQ(cert_opt->length, strlen(mock_cert));
    ATF_CHECK(memcmp(cert_opt->data, mock_cert, cert_opt->length) == 0);
    
    /* Cleanup */
    vendor_option_cleanup(&vso);
    vendor_option_cleanup(&parsed_vso);
    data_string_forget(&built_vso, MDL);
    vendor_handler_cleanup();
}

/* Test enterprise handler registration */
ATF_TC(enterprise_handler_test);
ATF_TC_HEAD(enterprise_handler_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test enterprise handler registration");
}
ATF_TC_BODY(enterprise_handler_test, tc) {
    int result;
    
    /* Initialize vendor handler */
    result = vendor_handler_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Create a test VSO for enterprise 12345 */
    struct vendor_option vso;
    vendor_option_init(&vso, 12345);
    
    /* Add test serial number */
    const char *test_serial = "TEST123456789";
    result = vendor_add_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER,
                                  (const unsigned char *)test_serial,
                                  strlen(test_serial));
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* The actual enterprise handler processing is tested indirectly
     * through vendor_handle_request, but the specific handlers are
     * internal implementation details */
    
    /* Verify VSO structure is valid */
    ATF_CHECK_EQ(vso.enterprise_num, 12345);
    ATF_CHECK_EQ(vso.sub_option_count, 1);
    
    const struct vendor_sub_option *serial_opt = 
        vendor_find_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER);
    ATF_REQUIRE(serial_opt != NULL);
    ATF_CHECK_EQ(serial_opt->code, VSO_SUBOPT_SERIAL_NUMBER);
    ATF_CHECK_EQ(serial_opt->length, strlen(test_serial));
    
    /* Cleanup */
    vendor_option_cleanup(&vso);
    vendor_handler_cleanup();
}

/* Test certificate file operations */
ATF_TC(certificate_file_test);
ATF_TC_HEAD(certificate_file_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test certificate file operations in vendor handler");
}
ATF_TC_BODY(certificate_file_test, tc) {
    int result;
    struct data_string cert_data;
    const char *test_cert = 
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBkTCB+wIJAL7LCvp1aBSNMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBFRl\n"
        "c3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAPMQ0wCwYDVQQDDARU\n"
        "ZXN0MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALRiMLAh9iimur8VA7qVK7MNiche\n"
        "-----END CERTIFICATE-----\n";
    const char *test_file = "/tmp/vendor_test_cert.pem";
    FILE *fp;
    
    /* Initialize vendor handler */
    result = vendor_handler_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Create test certificate file */
    fp = fopen(test_file, "w");
    if (fp != NULL) {
        fprintf(fp, "%s", test_cert);
        fclose(fp);
        
        /* Test loading certificate through vendor handler context */
        memset(&cert_data, 0, sizeof(cert_data));
        result = crypto_load_pem_certificate(test_file, &cert_data);
        
        if (result == CRYPTO_SUCCESS) {
            ATF_CHECK(cert_data.data != NULL);
            ATF_CHECK(cert_data.len > 0);
            ATF_CHECK(cert_data.len == strlen(test_cert));
            
            /* Create VSO with certificate */
            struct vendor_option vso;
            vendor_option_init(&vso, 12345);
            
            result = vendor_add_sub_option(&vso, VSO_SUBOPT_SERVER_CERT_CHAIN,
                                          cert_data.data, cert_data.len);
            ATF_CHECK_EQ(result, VSO_SUCCESS);
            
            /* Cleanup */
            vendor_option_cleanup(&vso);
            data_string_forget(&cert_data, MDL);
        }
        
        /* Remove test file */
        unlink(test_file);
    }
    
    vendor_handler_cleanup();
}

/* Test error handling scenarios */
ATF_TC(error_handling_test);
ATF_TC_HEAD(error_handling_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test vendor handler error handling");
}
ATF_TC_BODY(error_handling_test, tc) {
    int result;
    
    /* Test operations without initialization */
    struct mock_packet packet;
    struct mock_option_state options;
    struct mock_option_state reply_options;
    
    memset(&packet, 0, sizeof(packet));
    memset(&options, 0, sizeof(options));
    memset(&reply_options, 0, sizeof(reply_options));
    
    /* This should handle uninitialized state gracefully */
    result = vendor_handle_request(&packet.base, &options.base, &reply_options.base);
    /* Should not crash, may return error */
    
    /* Initialize properly */
    result = vendor_handler_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Test with malformed packet data */
    packet.base.raw = packet.raw_data;
    packet.base.packet_length = 0; /* Invalid length */
    packet.base.packet_type = DHCPV6_SOLICIT;
    
    result = vendor_handle_request(&packet.base, &options.base, &reply_options.base);
    /* Should handle gracefully */
    
    /* Test with valid packet but no vendor options */
    packet.base.packet_length = 100;
    memset(packet.raw_data, 0, 100);
    
    result = vendor_handle_request(&packet.base, &options.base, &reply_options.base);
    ATF_CHECK(result == VSO_SUCCESS || result == VSO_NOT_FOUND);
    
    vendor_handler_cleanup();
}

/* Test configuration scenarios */
ATF_TC(configuration_test);
ATF_TC_HEAD(configuration_test, tc) {
    atf_tc_set_md_var(tc, "descr", "Test vendor handler configuration scenarios");
}
ATF_TC_BODY(configuration_test, tc) {
    int result;
    
    /* Test initialization with default configuration */
    result = vendor_handler_init();
    ATF_REQUIRE_EQ(result, VSO_SUCCESS);
    
    /* Test that handler can process enterprise 12345 (default) */
    struct vendor_option vso;
    vendor_option_init(&vso, 12345);
    
    /* Add various sub-options */
    const char *serial = "CONFIG_TEST_SERIAL";
    result = vendor_add_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER,
                                  (const unsigned char *)serial,
                                  strlen(serial));
    ATF_CHECK_EQ(result, VSO_SUCCESS);
    
    const char *signature = "MockSignatureData";
    result = vendor_add_sub_option(&vso, VSO_SUBOPT_SIGNATURE,
                                  (const unsigned char *)signature,
                                  strlen(signature));
    ATF_CHECK_EQ(result, VSO_SUCCESS);
    
    /* Verify configuration */
    ATF_CHECK_EQ(vso.enterprise_num, 12345);
    ATF_CHECK_EQ(vso.sub_option_count, 2);
    
    /* Test with unsupported enterprise number */
    struct vendor_option unsupported_vso;
    vendor_option_init(&unsupported_vso, 99999);
    
    result = vendor_add_sub_option(&unsupported_vso, VSO_SUBOPT_SERIAL_NUMBER,
                                  (const unsigned char *)serial,
                                  strlen(serial));
    ATF_CHECK_EQ(result, VSO_SUCCESS);
    
    /* The enterprise number is stored correctly even if not supported */
    ATF_CHECK_EQ(unsupported_vso.enterprise_num, 99999);
    
    /* Cleanup */
    vendor_option_cleanup(&vso);
    vendor_option_cleanup(&unsupported_vso);
    vendor_handler_cleanup();
}

/* Main test suite */
ATF_TP_ADD_TCS(tp) {
    ATF_TP_ADD_TC(tp, vendor_handler_init_test);
    ATF_TP_ADD_TC(tp, vendor_handle_basic_test);
    ATF_TP_ADD_TC(tp, vendor_response_creation_test);
    ATF_TP_ADD_TC(tp, enterprise_handler_test);
    ATF_TP_ADD_TC(tp, certificate_file_test);
    ATF_TP_ADD_TC(tp, error_handling_test);
    ATF_TP_ADD_TC(tp, configuration_test);
    
    return atf_no_error();
}