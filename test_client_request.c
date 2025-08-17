#include "dhcpd.h"
#include "vendor_options.h"

/* Forward declarations for client vendor functions */
int client_vendor_init(void);
void client_vendor_cleanup(void);
int client_vendor_generate_request(struct option_state *options);
int client_vendor_enabled(void);

int main(int argc, char **argv) {
    struct option_state *options = NULL;
    int result;
    
    printf("DHCPv6 Client Vendor Request Test\n");
    printf("=================================\n");
    
    /* Initialize client vendor handler */
    result = client_vendor_init();
    if (result != 0) {
        printf("FAIL: client_vendor_init returned %d\n", result);
        return 1;
    }
    printf("PASS: Client vendor handler initialized\n");
    
    /* Check if vendor is enabled */
    if (!client_vendor_enabled()) {
        printf("FAIL: Client vendor not enabled\n");
        client_vendor_cleanup();
        return 1;
    }
    printf("PASS: Client vendor enabled\n");
    
    /* Allocate option state */
    options = dmalloc(sizeof(struct option_state), MDL);
    if (!options) {
        printf("FAIL: Failed to allocate option state\n");
        client_vendor_cleanup();
        return 1;
    }
    memset(options, 0, sizeof(struct option_state));
    
    /* Generate vendor request */
    result = client_vendor_generate_request(options);
    if (result != 0) {
        printf("FAIL: client_vendor_generate_request returned %d\n", result);
        dfree(options, MDL);
        client_vendor_cleanup();
        return 1;
    }
    printf("PASS: Vendor request generated successfully\n");
    
    /* Check if vendor option was added */
    struct option_cache *oc = lookup_option(&dhcpv6_universe, options, D6O_VENDOR_OPTS);
    if (!oc) {
        printf("FAIL: No vendor option found in request\n");
        dfree(options, MDL);
        client_vendor_cleanup();
        return 1;
    }
    printf("PASS: Vendor option (17) found in request\n");
    
    /* Clean up */
    dfree(options, MDL);
    client_vendor_cleanup();
    
    printf("\nResult: CLIENT REQUEST TEST PASSED ✓\n");
    printf("DHCPv6 client can generate vendor-specific option requests\n");
    
    return 0;
}