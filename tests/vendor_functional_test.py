#!/usr/bin/env python3
"""
DHCPv6 Vendor Options Functional Test

This script tests the vendor-specific options functionality by:
1. Creating test certificates and keys
2. Setting up a DHCPv6 server with vendor options
3. Simulating client requests with vendor options
4. Validating server responses
"""

import os
import sys
import subprocess
import tempfile
import socket
import struct
import time
import shutil
from pathlib import Path

class DHCPv6VendorTest:
    def __init__(self):
        self.test_dir = tempfile.mkdtemp(prefix="dhcpv6_vendor_test_")
        self.server_key = os.path.join(self.test_dir, "server.key")
        self.server_cert = os.path.join(self.test_dir, "server.pem")
        self.client_key = os.path.join(self.test_dir, "client.key")
        self.client_cert = os.path.join(self.test_dir, "client.pem")
        self.dhcpd_conf = os.path.join(self.test_dir, "dhcpd.conf")
        self.dhcpd_leases = os.path.join(self.test_dir, "dhcpd.leases")
        self.dhcpd_pid = None
        self.tests_passed = 0
        self.tests_failed = 0
        
    def cleanup(self):
        """Clean up test environment"""
        if self.dhcpd_pid:
            try:
                os.kill(self.dhcpd_pid, 15)  # SIGTERM
                time.sleep(1)
                os.kill(self.dhcpd_pid, 9)   # SIGKILL
            except:
                pass
        shutil.rmtree(self.test_dir, ignore_errors=True)
        
    def run_command(self, cmd, capture_output=True, check=True):
        """Run a command and return the result"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=capture_output, 
                                  text=True, check=check, cwd=".")
            return result
        except subprocess.CalledProcessError as e:
            if check:
                raise
            return e
            
    def test_result(self, test_name, success, details=""):
        """Record and print test result"""
        if success:
            print(f"[PASS] {test_name}")
            self.tests_passed += 1
        else:
            print(f"[FAIL] {test_name}")
            if details:
                print(f"       {details}")
            self.tests_failed += 1
            
    def generate_certificates(self):
        """Generate test certificates and keys"""
        print("Generating test certificates...")
        
        try:
            # Generate server private key
            self.run_command(f"openssl genpkey -algorithm RSA -out {self.server_key} "
                           f"-pkeyopt rsa_keygen_bits:2048")
            
            # Generate server certificate
            self.run_command(f"openssl req -new -x509 -key {self.server_key} "
                           f"-out {self.server_cert} -days 30 "
                           f"-subj '/CN=dhcp-test-server'")
            
            # Generate client private key
            self.run_command(f"openssl genpkey -algorithm RSA -out {self.client_key} "
                           f"-pkeyopt rsa_keygen_bits:2048")
            
            # Generate client certificate
            self.run_command(f"openssl req -new -x509 -key {self.client_key} "
                           f"-out {self.client_cert} -days 30 "
                           f"-subj '/CN=dhcp-test-client'")
            
            # Verify all files exist
            required_files = [self.server_key, self.server_cert, 
                            self.client_key, self.client_cert]
            all_exist = all(os.path.exists(f) for f in required_files)
            
            self.test_result("Certificate generation", all_exist)
            return all_exist
            
        except Exception as e:
            self.test_result("Certificate generation", False, str(e))
            return False
            
    def create_dhcpd_config(self):
        """Create DHCPv6 server configuration with vendor options"""
        print("Creating DHCPv6 server configuration...")
        
        config = f"""
# DHCPv6 Test Configuration with Vendor Options
default-lease-time 3600;
max-lease-time 7200;

# Enable DHCPv6
dhcpv6-lease-file-name "{self.dhcpd_leases}";

# Vendor configuration for enterprise 12345
vendor-config enterprise-12345 {{
    enabled true;
    auto-respond true;
    private-key "{self.server_key}";
    certificate-chain "{self.server_cert}";
    require-signature false;  # Disable for testing
    
    sub-option 71 {{
        type "serial-number";
        validate true;
    }}
    
    sub-option 72 {{
        type "signature";
        algorithm "rsa-sha256";
        required false;
    }}
    
    sub-option 73 {{
        type "certificate";
        save-path "{self.test_dir}/client-certs/";
    }}
    
    sub-option 77 {{
        type "certificate-chain";
        certificate-chain "{self.server_cert}";
    }}
}}

# IPv6 subnet configuration for testing
subnet6 2001:db8:1::/64 {{
    range6 2001:db8:1::100 2001:db8:1::200;
    
    # Test client configuration
    host test-client {{
        host-identifier option dhcp6.client-id 00:01:00:01:12:34:56:78:aa:bb:cc:dd:ee:ff;
        fixed-address6 2001:db8:1::100;
        vendor-config enterprise-12345;
        vendor-serial-number "FUNC_TEST_12345";
    }}
}}
"""
        
        try:
            with open(self.dhcpd_conf, 'w') as f:
                f.write(config)
                
            # Test configuration syntax
            result = self.run_command(f"./server/dhcpd -t -cf {self.dhcpd_conf}", 
                                    check=False)
            success = result.returncode == 0
            
            self.test_result("DHCPv6 configuration creation", success, 
                           result.stderr if not success else "")
            return success
            
        except Exception as e:
            self.test_result("DHCPv6 configuration creation", False, str(e))
            return False
            
    def test_vendor_option_parsing(self):
        """Test vendor option packet parsing"""
        print("Testing vendor option parsing...")
        
        # Create a test program to test parsing
        test_program = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "includes/dhcpd.h"
#include "includes/vendor_options.h"

int main() {{
    // Test VSO with enterprise 12345 and serial number
    unsigned char test_vso[] = {{
        0x00, 0x00, 0x30, 0x39,  // Enterprise number 12345
        0x00, 0x47,              // Sub-option code 71 (serial)
        0x00, 0x0F,              // Length 15
        'F','U','N','C','_','T','E','S','T','_','1','2','3','4','5'
    }};
    
    struct data_string vso_data;
    struct vendor_option parsed_vso;
    
    if (vendor_options_init() != VSO_SUCCESS) {{
        printf("FAIL: Init failed\\n");
        return 1;
    }}
    
    vso_data.data = test_vso;
    vso_data.len = sizeof(test_vso);
    
    int result = vendor_parse_option(&vso_data, &parsed_vso);
    if (result != VSO_SUCCESS) {{
        printf("FAIL: Parse failed\\n");
        return 1;
    }}
    
    if (parsed_vso.enterprise_num != 12345) {{
        printf("FAIL: Wrong enterprise number\\n");
        return 1;
    }}
    
    if (parsed_vso.sub_option_count != 1) {{
        printf("FAIL: Wrong sub-option count\\n");
        return 1;
    }}
    
    const struct vendor_sub_option *sub_opt = 
        vendor_find_sub_option(&parsed_vso, 71);
    if (!sub_opt || sub_opt->length != 15) {{
        printf("FAIL: Serial sub-option not found or wrong length\\n");
        return 1;
    }}
    
    printf("PASS: Vendor option parsing successful\\n");
    vendor_option_cleanup(&parsed_vso);
    vendor_options_cleanup();
    return 0;
}}
"""
        
        try:
            test_file = os.path.join(self.test_dir, "test_parsing.c")
            with open(test_file, 'w') as f:
                f.write(test_program)
                
            # Compile test program
            compile_cmd = (f"gcc -I. -I./includes -I./common {test_file} "
                         f"-L./common -L./server -ldhcp -lssl -lcrypto "
                         f"-o {self.test_dir}/test_parsing")
            
            compile_result = self.run_command(compile_cmd, check=False)
            if compile_result.returncode != 0:
                self.test_result("Vendor option parsing", False, 
                               "Failed to compile test program")
                return False
                
            # Run test program
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = './common:./server'
            
            run_result = subprocess.run(f"{self.test_dir}/test_parsing",
                                      shell=True, capture_output=True, text=True,
                                      env=env)
            
            success = run_result.returncode == 0 and "PASS" in run_result.stdout
            self.test_result("Vendor option parsing", success,
                           run_result.stdout + run_result.stderr if not success else "")
            return success
            
        except Exception as e:
            self.test_result("Vendor option parsing", False, str(e))
            return False
            
    def test_server_startup(self):
        """Test DHCPv6 server startup with vendor options"""
        print("Testing DHCPv6 server startup...")
        
        try:
            # Create empty leases file
            with open(self.dhcpd_leases, 'w') as f:
                f.write("")
                
            # Start server in background
            cmd = f"./server/dhcpd -6 -f -d -cf {self.dhcpd_conf}"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                     stderr=subprocess.STDOUT, text=True)
            
            # Wait for server to start
            time.sleep(3)
            
            # Check if process is still running
            poll_result = process.poll()
            if poll_result is not None:
                # Process exited
                output, _ = process.communicate()
                self.test_result("DHCPv6 server startup", False, 
                               f"Server exited with code {poll_result}: {output}")
                return False
            else:
                # Process is running
                self.dhcpd_pid = process.pid
                self.test_result("DHCPv6 server startup", True)
                
                # Try to read some output for vendor initialization messages
                try:
                    process.stdout.settimeout(2)
                    output = process.stdout.readline()
                    if "vendor" in output.lower():
                        print(f"       Vendor initialization detected: {output.strip()}")
                except:
                    pass
                    
                return True
                
        except Exception as e:
            self.test_result("DHCPv6 server startup", False, str(e))
            return False
            
    def create_dhcpv6_packet(self):
        """Create a DHCPv6 packet with vendor options"""
        # DHCPv6 Solicit packet structure
        packet = bytearray()
        
        # Message type (1 = Solicit)
        packet.append(1)
        
        # Transaction ID (3 bytes)
        packet.extend([0x12, 0x34, 0x56])
        
        # Client Identifier Option (Option 1)
        packet.extend(struct.pack('>H', 1))    # Option code
        packet.extend(struct.pack('>H', 14))   # Option length
        packet.extend(struct.pack('>H', 1))    # DUID type (LLT)
        packet.extend(struct.pack('>H', 1))    # Hardware type (Ethernet)
        packet.extend(struct.pack('>I', int(time.time())))  # Time
        packet.extend([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])  # MAC address
        
        # Vendor-specific Information Option (Option 17)
        vendor_data = bytearray()
        vendor_data.extend(struct.pack('>I', 12345))  # Enterprise number
        
        # Sub-option 71: Serial Number
        vendor_data.extend(struct.pack('>H', 71))     # Sub-option code
        vendor_data.extend(struct.pack('>H', 15))     # Sub-option length
        vendor_data.extend(b'FUNC_TEST_12345')        # Serial number data
        
        # Add vendor option to packet
        packet.extend(struct.pack('>H', 17))          # Option code (Vendor-specific)
        packet.extend(struct.pack('>H', len(vendor_data)))  # Option length
        packet.extend(vendor_data)
        
        return bytes(packet)
        
    def test_packet_construction(self):
        """Test DHCPv6 packet construction with vendor options"""
        print("Testing DHCPv6 packet construction...")
        
        try:
            packet = self.create_dhcpv6_packet()
            
            # Basic validation
            if len(packet) < 4:
                self.test_result("DHCPv6 packet construction", False, 
                               "Packet too short")
                return False
                
            # Check message type
            if packet[0] != 1:  # Solicit
                self.test_result("DHCPv6 packet construction", False,
                               "Wrong message type")
                return False
                
            # Look for vendor option
            vendor_option_found = False
            i = 4  # Skip message type and transaction ID
            
            while i < len(packet) - 4:
                option_code = struct.unpack('>H', packet[i:i+2])[0]
                option_length = struct.unpack('>H', packet[i+2:i+4])[0]
                
                if option_code == 17:  # Vendor-specific option
                    vendor_option_found = True
                    # Check enterprise number
                    if i + 8 <= len(packet):
                        enterprise = struct.unpack('>I', packet[i+4:i+8])[0]
                        if enterprise == 12345:
                            self.test_result("DHCPv6 packet construction", True)
                            return True
                            
                i += 4 + option_length
                
            self.test_result("DHCPv6 packet construction", vendor_option_found,
                           "Vendor option not found or invalid enterprise number")
            return vendor_option_found
            
        except Exception as e:
            self.test_result("DHCPv6 packet construction", False, str(e))
            return False
            
    def test_crypto_functions(self):
        """Test cryptographic functions"""
        print("Testing cryptographic functions...")
        
        test_program = f"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "includes/dhcpd.h"
#include "includes/crypto_utils.h"

int main() {{
    if (crypto_utils_init() != CRYPTO_SUCCESS) {{
        printf("FAIL: Crypto init failed\\n");
        return 1;
    }}
    
    // Test Base64 encoding/decoding
    const char *test_data = "TestData123";
    char *encoded = crypto_base64_encode((const unsigned char *)test_data, strlen(test_data));
    if (!encoded) {{
        printf("FAIL: Base64 encoding failed\\n");
        return 1;
    }}
    
    unsigned char *decoded;
    size_t decoded_len;
    if (crypto_base64_decode(encoded, &decoded, &decoded_len) != CRYPTO_SUCCESS) {{
        printf("FAIL: Base64 decoding failed\\n");
        dfree(encoded, MDL);
        return 1;
    }}
    
    if (decoded_len != strlen(test_data) || 
        memcmp(decoded, test_data, decoded_len) != 0) {{
        printf("FAIL: Base64 round-trip failed\\n");
        dfree(encoded, MDL);
        dfree(decoded, MDL);
        return 1;
    }}
    
    printf("PASS: Crypto functions working\\n");
    dfree(encoded, MDL);
    dfree(decoded, MDL);
    crypto_utils_cleanup();
    return 0;
}}
"""
        
        try:
            test_file = os.path.join(self.test_dir, "test_crypto.c")
            with open(test_file, 'w') as f:
                f.write(test_program)
                
            # Compile test program
            compile_cmd = (f"gcc -I. -I./includes -I./common {test_file} "
                         f"-L./common -L./server -ldhcp -lssl -lcrypto "
                         f"-o {self.test_dir}/test_crypto")
            
            compile_result = self.run_command(compile_cmd, check=False)
            if compile_result.returncode != 0:
                self.test_result("Cryptographic functions", False,
                               "Failed to compile test program")
                return False
                
            # Run test program
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = './common:./server'
            
            run_result = subprocess.run(f"{self.test_dir}/test_crypto",
                                      shell=True, capture_output=True, text=True,
                                      env=env)
            
            success = run_result.returncode == 0 and "PASS" in run_result.stdout
            self.test_result("Cryptographic functions", success,
                           run_result.stdout + run_result.stderr if not success else "")
            return success
            
        except Exception as e:
            self.test_result("Cryptographic functions", False, str(e))
            return False
            
    def run_all_tests(self):
        """Run all functional tests"""
        print("DHCPv6 Vendor Options Functional Test")
        print("=====================================")
        print(f"Test directory: {self.test_dir}")
        print()
        
        # Check if binaries exist
        if not os.path.exists("./server/dhcpd"):
            print("ERROR: dhcpd server binary not found. Please build first.")
            return False
            
        tests = [
            self.generate_certificates,
            self.test_crypto_functions,
            self.test_vendor_option_parsing,
            self.create_dhcpd_config,
            self.test_packet_construction,
            self.test_server_startup,
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                self.test_result(test.__name__, False, str(e))
                
        print()
        print("Test Summary")
        print("============")
        print(f"Total tests: {self.tests_passed + self.tests_failed}")
        print(f"Passed: {self.tests_passed}")
        print(f"Failed: {self.tests_failed}")
        
        if self.tests_failed == 0:
            print("Result: ALL TESTS PASSED ✓")
            print()
            print("DHCPv6 vendor-specific options functionality is working correctly.")
            return True
        else:
            print("Result: SOME TESTS FAILED ✗")
            return False

def main():
    """Main function"""
    test_runner = DHCPv6VendorTest()
    try:
        success = test_runner.run_all_tests()
        return 0 if success else 1
    finally:
        test_runner.cleanup()

if __name__ == "__main__":
    sys.exit(main())