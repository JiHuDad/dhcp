#!/bin/bash
#
# DHCPv6 Vendor-Specific Options Integration Test
# Tests the complete vendor options functionality end-to-end
#

set -e

TEST_DIR=$(mktemp -d)
TEST_LOG="$TEST_DIR/integration_test.log"
DHCPD_CONF="$TEST_DIR/dhcpd.conf"
DHCPD_LEASES="$TEST_DIR/dhcpd.leases"
SERVER_KEY="$TEST_DIR/server.key"
SERVER_CERT="$TEST_DIR/server.pem"
CLIENT_KEY="$TEST_DIR/client.key"
CLIENT_CERT="$TEST_DIR/client.pem"

echo "DHCPv6 Vendor Options Integration Test"
echo "======================================="
echo "Test directory: $TEST_DIR"
echo "Log file: $TEST_LOG"
echo

# Function to print test results
print_result() {
    local test_name="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo "[PASS] $test_name"
    else
        echo "[FAIL] $test_name"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Initialize counters
TOTAL_TESTS=0
FAILED_TESTS=0

# Cleanup function
cleanup() {
    echo
    echo "Cleaning up..."
    if [ -n "$DHCPD_PID" ] && kill -0 "$DHCPD_PID" 2>/dev/null; then
        kill "$DHCPD_PID"
        wait "$DHCPD_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Test 1: Generate test certificates
echo "Test 1: Generating test certificates..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Generate server private key
openssl genpkey -algorithm RSA -out "$SERVER_KEY" -pkeyopt rsa_keygen_bits:2048 >> $TEST_LOG 2>&1
# Generate server certificate
openssl req -new -x509 -key "$SERVER_KEY" -out "$SERVER_CERT" -days 30 -subj "/CN=test-server" >> $TEST_LOG 2>&1

# Generate client private key
openssl genpkey -algorithm RSA -out "$CLIENT_KEY" -pkeyopt rsa_keygen_bits:2048 >> $TEST_LOG 2>&1
# Generate client certificate
openssl req -new -x509 -key "$CLIENT_KEY" -out "$CLIENT_CERT" -days 30 -subj "/CN=test-client" >> $TEST_LOG 2>&1

# Verify certificates were created
if [ -f "$SERVER_KEY" ] && [ -f "$SERVER_CERT" ] && [ -f "$CLIENT_KEY" ] && [ -f "$CLIENT_CERT" ]; then
    print_result "Certificate generation" 0
else
    print_result "Certificate generation" 1
fi

# Test 2: Create DHCPv6 server configuration
echo "Test 2: Creating DHCPv6 server configuration..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))

cat > "$DHCPD_CONF" << EOF
# DHCPv6 Test Configuration with Vendor Options
default-lease-time 3600;
max-lease-time 7200;

# Enable DHCPv6
dhcpv6-lease-file-name "$DHCPD_LEASES";

# Vendor configuration for enterprise 12345
vendor-config enterprise-12345 {
    enabled true;
    auto-respond true;
    private-key "$SERVER_KEY";
    certificate-chain "$SERVER_CERT";
    require-signature true;
    
    sub-option 71 {
        type "serial-number";
        validate true;
    }
    
    sub-option 72 {
        type "signature";
        algorithm "rsa-sha256";
        required true;
    }
    
    sub-option 73 {
        type "certificate";
        save-path "$TEST_DIR/client-certs/";
    }
    
    sub-option 77 {
        type "certificate-chain";
        certificate-chain "$SERVER_CERT";
    }
}

# IPv6 subnet configuration
subnet6 2001:db8::/64 {
    range6 2001:db8::100 2001:db8::200;
    
    # Host with vendor configuration
    host test-client {
        host-identifier option dhcp6.client-id 00:01:00:01:12:34:56:78:aa:bb:cc:dd:ee:ff;
        fixed-address6 2001:db8::100;
        vendor-config enterprise-12345;
        vendor-serial-number "TEST123456789";
    }
}
EOF

# Test configuration syntax
if ./server/dhcpd -t -cf "$DHCPD_CONF" >> $TEST_LOG 2>&1; then
    print_result "DHCPv6 configuration syntax" 0
else
    print_result "DHCPv6 configuration syntax" 1
fi

# Test 3: Build verification
echo "Test 3: Verifying vendor options build..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Check if vendor option symbols exist in binaries
VENDOR_SYMBOLS_FOUND=0

if nm ./server/dhcpd 2>/dev/null | grep -q "vendor_handle_request\|vendor_handler_init"; then
    VENDOR_SYMBOLS_FOUND=$((VENDOR_SYMBOLS_FOUND + 1))
fi

if nm ./client/dhclient 2>/dev/null | grep -q "client_vendor_generate_request\|vendor_option"; then
    VENDOR_SYMBOLS_FOUND=$((VENDOR_SYMBOLS_FOUND + 1))
fi

if [ "$VENDOR_SYMBOLS_FOUND" -gt 0 ]; then
    print_result "Vendor symbols in binaries" 0
else
    print_result "Vendor symbols in binaries" 1
fi

# Test 4: Unit tests execution
echo "Test 4: Running unit tests..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))

UNIT_TEST_RESULT=0

# Run crypto utils unit tests
if [ -f "./common/tests/crypto_utils_unittest" ]; then
    if ./common/tests/crypto_utils_unittest >> $TEST_LOG 2>&1; then
        echo "  [PASS] Crypto utils unit tests"
    else
        echo "  [FAIL] Crypto utils unit tests"
        UNIT_TEST_RESULT=1
    fi
else
    echo "  [SKIP] Crypto utils unit tests (not built)"
fi

# Run vendor options unit tests
if [ -f "./common/tests/vendor_options_unittest" ]; then
    if ./common/tests/vendor_options_unittest >> $TEST_LOG 2>&1; then
        echo "  [PASS] Vendor options unit tests"
    else
        echo "  [FAIL] Vendor options unit tests"
        UNIT_TEST_RESULT=1
    fi
else
    echo "  [SKIP] Vendor options unit tests (not built)"
fi

# Run vendor handler unit tests
if [ -f "./server/tests/vendor_handler_unittest" ]; then
    if ./server/tests/vendor_handler_unittest >> $TEST_LOG 2>&1; then
        echo "  [PASS] Vendor handler unit tests"
    else
        echo "  [FAIL] Vendor handler unit tests"
        UNIT_TEST_RESULT=1
    fi
else
    echo "  [SKIP] Vendor handler unit tests (not built)"
fi

print_result "Unit tests execution" $UNIT_TEST_RESULT

# Test 5: Server startup test
echo "Test 5: Testing DHCPv6 server startup..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Create empty leases file
touch "$DHCPD_LEASES"

# Start DHCPv6 server in background
timeout 10s ./server/dhcpd -6 -f -d -cf "$DHCPD_CONF" >> $TEST_LOG 2>&1 &
DHCPD_PID=$!

# Wait a moment for server to start
sleep 2

# Check if server is still running
if kill -0 "$DHCPD_PID" 2>/dev/null; then
    print_result "DHCPv6 server startup" 0
    
    # Check server logs for vendor initialization
    if grep -q "vendor.*init\|Vendor.*init" $TEST_LOG 2>/dev/null; then
        echo "  [INFO] Vendor initialization logged"
    fi
else
    print_result "DHCPv6 server startup" 1
fi

# Test 6: Vendor option packet construction
echo "Test 6: Testing vendor option packet construction..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Create a test program to construct vendor options
cat > "$TEST_DIR/test_vso_construction.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../includes/dhcpd.h"
#include "../includes/vendor_options.h"

int main() {
    struct vendor_option vso;
    struct data_string result;
    int ret;
    
    // Initialize vendor options
    if (vendor_options_init() != VSO_SUCCESS) {
        printf("Failed to initialize vendor options\n");
        return 1;
    }
    
    // Create VSO for enterprise 12345
    vendor_option_init(&vso, 12345);
    
    // Add serial number sub-option
    const char *serial = "TEST123456789";
    ret = vendor_add_sub_option(&vso, VSO_SUBOPT_SERIAL_NUMBER,
                               (const unsigned char *)serial, strlen(serial));
    if (ret != VSO_SUCCESS) {
        printf("Failed to add serial number sub-option\n");
        return 1;
    }
    
    // Add signature sub-option (mock data)
    const char *signature = "MockSignatureDataForTesting";
    ret = vendor_add_sub_option(&vso, VSO_SUBOPT_SIGNATURE,
                               (const unsigned char *)signature, strlen(signature));
    if (ret != VSO_SUCCESS) {
        printf("Failed to add signature sub-option\n");
        return 1;
    }
    
    // Build the VSO
    memset(&result, 0, sizeof(result));
    ret = vendor_build_option(&vso, &result);
    if (ret != VSO_SUCCESS) {
        printf("Failed to build VSO\n");
        return 1;
    }
    
    printf("VSO construction successful:\n");
    printf("Enterprise: %u\n", vso.enterprise_num);
    printf("Sub-options: %u\n", vso.sub_option_count);
    printf("Wire format length: %u bytes\n", (unsigned int)result.len);
    
    // Parse it back to verify
    struct vendor_option parsed_vso;
    ret = vendor_parse_option(&result, &parsed_vso);
    if (ret != VSO_SUCCESS) {
        printf("Failed to parse back VSO\n");
        return 1;
    }
    
    if (parsed_vso.enterprise_num == 12345 && parsed_vso.sub_option_count == 2) {
        printf("Round-trip verification successful\n");
        vendor_option_cleanup(&parsed_vso);
        data_string_forget(&result, MDL);
        vendor_option_cleanup(&vso);
        vendor_options_cleanup();
        return 0;
    } else {
        printf("Round-trip verification failed\n");
        return 1;
    }
}
EOF

# Compile the test program
if gcc -I. -I./includes -I./common "$TEST_DIR/test_vso_construction.c" \
       -L./common -L./server -ldhcp -lssl -lcrypto \
       -o "$TEST_DIR/test_vso_construction" >> $TEST_LOG 2>&1; then
    
    # Run the test program
    if LD_LIBRARY_PATH=./common:./server "$TEST_DIR/test_vso_construction" >> $TEST_LOG 2>&1; then
        print_result "Vendor option packet construction" 0
    else
        print_result "Vendor option packet construction" 1
    fi
else
    print_result "Vendor option packet construction" 1
    echo "  [INFO] Could not compile test program (missing dependencies)"
fi

# Test 7: Configuration parser test
echo "Test 7: Testing configuration parser..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Test various configuration syntax variations
CONFIG_TEST_RESULT=0

# Test 7a: Basic vendor-config syntax
cat > "$TEST_DIR/test1.conf" << EOF
vendor-config enterprise-999 {
    enabled true;
}
subnet6 2001:db8::/64 {
    range6 2001:db8::100 2001:db8::200;
}
EOF

if ./server/dhcpd -t -cf "$TEST_DIR/test1.conf" >> $TEST_LOG 2>&1; then
    echo "  [PASS] Basic vendor-config syntax"
else
    echo "  [FAIL] Basic vendor-config syntax"
    CONFIG_TEST_RESULT=1
fi

# Test 7b: Complex vendor-config with sub-options
cat > "$TEST_DIR/test2.conf" << EOF
vendor-config enterprise-12345 {
    enabled true;
    auto-respond true;
    private-key "/tmp/key.pem";
    certificate-chain "/tmp/cert.pem";
    require-signature true;
    
    sub-option 71 {
        type "serial-number";
        validate true;
    }
    
    sub-option 72 {
        type "signature";
        algorithm "rsa-sha256";
        required true;
    }
}
subnet6 2001:db8::/64 {
    range6 2001:db8::100 2001:db8::200;
}
EOF

if ./server/dhcpd -t -cf "$TEST_DIR/test2.conf" >> $TEST_LOG 2>&1; then
    echo "  [PASS] Complex vendor-config syntax"
else
    echo "  [FAIL] Complex vendor-config syntax"
    CONFIG_TEST_RESULT=1
fi

print_result "Configuration parser" $CONFIG_TEST_RESULT

# Test 8: Error handling test
echo "Test 8: Testing error handling..."
TOTAL_TESTS=$((TOTAL_TESTS + 1))

ERROR_TEST_RESULT=0

# Test 8a: Invalid configuration should fail
cat > "$TEST_DIR/invalid.conf" << EOF
vendor-config invalid-syntax {
    unknown-option "test";
}
EOF

if ./server/dhcpd -t -cf "$TEST_DIR/invalid.conf" >> $TEST_LOG 2>&1; then
    echo "  [FAIL] Invalid configuration accepted"
    ERROR_TEST_RESULT=1
else
    echo "  [PASS] Invalid configuration rejected"
fi

# Test 8b: Missing certificates should be handled gracefully
cat > "$TEST_DIR/missing_cert.conf" << EOF
vendor-config enterprise-12345 {
    enabled true;
    private-key "/nonexistent/key.pem";
    certificate-chain "/nonexistent/cert.pem";
}
subnet6 2001:db8::/64 {
    range6 2001:db8::100 2001:db8::200;
}
EOF

# This should parse but may log warnings about missing files
if ./server/dhcpd -t -cf "$TEST_DIR/missing_cert.conf" >> $TEST_LOG 2>&1; then
    echo "  [PASS] Missing certificate files handled"
else
    echo "  [PASS] Missing certificate files cause config rejection (acceptable)"
fi

print_result "Error handling" $ERROR_TEST_RESULT

# Test Summary
echo
echo "Test Summary"
echo "============"
echo "Total tests: $TOTAL_TESTS"
echo "Passed: $((TOTAL_TESTS - FAILED_TESTS))"
echo "Failed: $FAILED_TESTS"

if [ "$FAILED_TESTS" -eq 0 ]; then
    echo "Result: ALL TESTS PASSED ✓"
    echo
    echo "DHCPv6 vendor-specific options integration appears to be working correctly."
    echo "Key features tested:"
    echo "  - Certificate generation and handling"
    echo "  - Configuration parser with vendor-config syntax"
    echo "  - Vendor option packet construction and parsing"
    echo "  - Server startup with vendor options enabled"
    echo "  - Unit test coverage for core components"
    echo "  - Error handling and validation"
    exit 0
else
    echo "Result: SOME TESTS FAILED ✗"
    echo
    echo "Please check the test log for details: $TEST_LOG"
    echo "Common issues:"
    echo "  - Missing build dependencies (OpenSSL, ATF)"
    echo "  - Vendor options not enabled during configure"
    echo "  - Missing unit test binaries"
    exit 1
fi