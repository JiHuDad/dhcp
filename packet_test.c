#include "dhcpd.h"
#include "vendor_options.h"

int main(int argc, char **argv) {
    struct vendor_option vso;
    struct data_string wire_data;
    const char *test_data = "Hello Vendor";
    
    printf("DHCPv6 Vendor Packet Test\n");
    printf("=========================\n");
    
    // Initialize
    if (vendor_options_init() != VSO_SUCCESS) {
        printf("FAIL: vendor_options_init\n");
        return 1;
    }
    
    // Initialize VSO
    memset(&vso, 0, sizeof(vso));
    vso.enterprise_num = 12345;
    
    // Add test sub-options
    if (vendor_add_sub_option(&vso, 71, (unsigned char*)test_data, strlen(test_data)) != VSO_SUCCESS) {
        printf("FAIL: vendor_add_sub_option\n");
        return 1;
    }
    
    // Build packet data
    if (vendor_build_option(&vso, &wire_data) != VSO_SUCCESS) {
        printf("FAIL: vendor_build_option\n");
        return 1;
    }
    
    printf("PASS: Packet generation successful\n");
    printf("  Wire format: %u bytes\n", wire_data.len);
    printf("  Enterprise: %u\n", vso.enterprise_num);
    printf("  Sub-options: %d\n", vso.sub_option_count);
    
    // Parse it back
    struct vendor_option parsed_vso;
    if (vendor_parse_option(&wire_data, &parsed_vso) != VSO_SUCCESS) {
        printf("FAIL: vendor_parse_option\n");
        return 1;
    }
    
    printf("PASS: Packet parsing successful\n");
    printf("  Parsed enterprise: %u\n", parsed_vso.enterprise_num);
    printf("  Parsed sub-options: %d\n", parsed_vso.sub_option_count);
    
    // Cleanup
    vendor_option_cleanup(&vso);
    vendor_option_cleanup(&parsed_vso);
    data_string_forget(&wire_data, MDL);
    vendor_options_cleanup();
    
    printf("\nResult: ALL PACKET TESTS PASSED ✓\n");
    return 0;
}
