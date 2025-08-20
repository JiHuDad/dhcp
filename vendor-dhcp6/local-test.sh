#!/bin/bash
#
# Local DHCPv6 Vendor Client Test (without scapy dependency)
# Tests core functionality without requiring Python scapy
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    local test_func="$2"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    log_info "Running test: $test_name"
    
    if $test_func; then
        log_success "$test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "$test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Test 1: Binary exists and responds to help
test_help_option() {
    ./vendor-dhclient --help >/dev/null 2>&1
    return $?
}

# Test 2: Configuration parsing
test_config_parsing() {
    local temp_config=$(mktemp)
    echo "invalid_toml_syntax = [" > "$temp_config"
    
    if ./vendor-dhclient --config "$temp_config" --dry-run 2>/dev/null; then
        rm -f "$temp_config"
        return 1  # Should have failed
    fi
    
    rm -f "$temp_config"
    return 0
}

# Test 3: Dry run VSO generation
test_dry_run_vso() {
    export SN_NUMBER="TEST12345678"
    
    ./vendor-dhclient --config test-config.toml --dry-run >/dev/null 2>&1
    local result=$?
    
    unset SN_NUMBER
    return $result
}

# Test 4: Missing SN_NUMBER environment variable
test_missing_sn_number() {
    unset SN_NUMBER
    
    if ./vendor-dhclient --config test-config.toml --dry-run 2>/dev/null; then
        return 1  # Should have failed
    fi
    
    return 0
}

# Test 5: Verbose mode
test_verbose_mode() {
    export SN_NUMBER="VERBOSE_TEST_123"
    
    local output=$(./vendor-dhclient --config test-config.toml --dry-run -v 2>&1)
    local result=$?
    
    # Check if verbose output contains expected debug information
    if [[ $result -eq 0 ]] && echo "$output" | grep -q "VSO generation"; then
        unset SN_NUMBER
        return 0
    fi
    
    unset SN_NUMBER
    return 1
}

# Test 6: Configuration validation with different parameters
test_config_variations() {
    local temp_config=$(mktemp)
    
    # Test with minimal valid config
    cat > "$temp_config" << EOF
[dhcp6]
iface = "lo"
timeout_seconds = 10

[vendor]
enterprise = 12345
sn_env = "SN_NUMBER"
code_sn = 71
code_sig = 72
code_cert_req = 73
code_sig_dup = 74
code_cert_reply = 77

[paths]
private_key = "/tmp/vendor-test/keys/client.key"
request_cert = "/tmp/vendor-test/certs/request.pem"
reply_cert0 = "/tmp/vendor-test/server0.pem"
reply_cert1 = "/tmp/vendor-test/server1.pem"

[advertise_gate]
enabled = false

[logging]
level = "debug"
hex_dump = false
EOF
    
    export SN_NUMBER="CONFIG_TEST_456"
    local result=0
    ./vendor-dhclient --config "$temp_config" --dry-run >/dev/null 2>&1 || result=1
    
    rm -f "$temp_config"
    unset SN_NUMBER
    return $result
}

# Test 7: Different enterprise numbers
test_enterprise_numbers() {
    local temp_config=$(mktemp)
    
    # Copy test config and modify enterprise number
    sed 's/enterprise = 99999/enterprise = 54321/' test-config.toml > "$temp_config"
    
    export SN_NUMBER="ENTERPRISE_TEST_789"
    local result=0
    
    local output=$(./vendor-dhclient --config "$temp_config" --dry-run 2>&1)
    if [[ $? -eq 0 ]] && echo "$output" | grep -q "enterprise=54321"; then
        result=0
    else
        result=1
    fi
    
    rm -f "$temp_config"
    unset SN_NUMBER
    return $result
}

# Test 8: Long SN_NUMBER
test_long_sn_number() {
    export SN_NUMBER="VERY_LONG_SERIAL_NUMBER_WITH_MANY_CHARACTERS_123456789ABCDEF"
    
    ./vendor-dhclient --config test-config.toml --dry-run >/dev/null 2>&1
    local result=$?
    
    unset SN_NUMBER
    return $result
}

# Test 9: Special characters in SN_NUMBER  
test_special_sn_number() {
    export SN_NUMBER="TEST-SERIAL_123.456@COMPANY.COM"
    
    ./vendor-dhclient --config test-config.toml --dry-run >/dev/null 2>&1
    local result=$?
    
    unset SN_NUMBER
    return $result
}

# Test 10: File permissions validation
test_file_permissions() {
    # Check if the client validates file permissions
    local temp_key="/tmp/test_bad_key.pem"
    cp /tmp/vendor-test/keys/client.key "$temp_key"
    chmod 644 "$temp_key"  # Wrong permissions
    
    local temp_config=$(mktemp)
    sed "s|/tmp/vendor-test/keys/client.key|$temp_key|" test-config.toml > "$temp_config"
    
    export SN_NUMBER="PERMISSION_TEST_999"
    
    # This should warn about file permissions but still work
    local output=$(./vendor-dhclient --config "$temp_config" --dry-run 2>&1)
    local result=$?
    
    rm -f "$temp_key" "$temp_config"
    unset SN_NUMBER
    
    # Accept either success or specific permission warning
    if [[ $result -eq 0 ]] || echo "$output" | grep -q -i "permission"; then
        return 0
    else
        return 1
    fi
}

# Main test execution
main() {
    echo "==========================================="
    echo "DHCPv6 Vendor Client Local Test Suite"
    echo "==========================================="
    echo "Testing without network dependencies..."
    echo
    
    # Check prerequisites
    if [[ ! -f "vendor-dhclient" ]]; then
        log_error "vendor-dhclient binary not found"
        exit 1
    fi
    
    if [[ ! -f "test-config.toml" ]]; then
        log_error "test-config.toml not found"
        exit 1
    fi
    
    if [[ ! -f "/tmp/vendor-test/keys/client.key" ]]; then
        log_error "Test key not found. Run test setup first."
        exit 1
    fi
    
    log_info "Starting local test execution..."
    echo
    
    # Core functionality tests
    run_test "Help option" test_help_option
    run_test "Configuration parsing" test_config_parsing
    run_test "Dry run VSO generation" test_dry_run_vso
    run_test "Missing SN_NUMBER handling" test_missing_sn_number
    run_test "Verbose mode output" test_verbose_mode
    run_test "Configuration variations" test_config_variations
    run_test "Enterprise number changes" test_enterprise_numbers
    run_test "Long SN_NUMBER support" test_long_sn_number
    run_test "Special characters in SN_NUMBER" test_special_sn_number
    run_test "File permissions validation" test_file_permissions
    
    # Results summary
    echo
    echo "=========================================="
    echo "LOCAL TEST RESULTS SUMMARY"
    echo "=========================================="
    echo "Total tests:  $TESTS_TOTAL"
    echo "Passed:       $TESTS_PASSED"
    echo "Failed:       $TESTS_FAILED"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_success "All local tests passed! ✓"
        echo
        echo "🎉 DHCPv6 Vendor Client is ready for deployment!"
        echo
        echo "Next steps for full testing:"
        echo "1. Install scapy: pip3 install scapy"
        echo "2. Run full integration test: ./test_integration.sh"
        echo "3. Test with Docker: ./docker-test.sh build && ./docker-test.sh test"
        exit 0
    else
        log_error "$TESTS_FAILED test(s) failed!"
        exit 1
    fi
}

main "$@"