#!/usr/bin/env python3
"""
Fake DHCPv6 Server for testing vendor client
Uses scapy to generate Advertise and Reply messages with VSO
"""

import sys
import time
import socket
import struct
from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.dhcp6 import *

# DHCPv6 Message Types
DHCPV6_SOLICIT = 1
DHCPV6_ADVERTISE = 2
DHCPV6_REQUEST = 3
DHCPV6_REPLY = 7

# DHCPv6 Options
DHCPV6_OPT_CLIENTID = 1
DHCPV6_OPT_SERVERID = 2
DHCPV6_OPT_VENDOR_OPTS = 17

class FakeDHCPv6Server:
    def __init__(self, interface="lo", enterprise=99999):
        self.interface = interface
        self.enterprise = enterprise
        self.server_duid = b'\x00\x01\x00\x01\x12\x34\x56\x78\x00\x11\x22\x33\x44\x55'
        
        # Test certificates for VSO sub-option 77
        self.cert1 = """-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDKVaBh8W8+5jANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNDEyMTAxMDAwMDBaFw0yNTEyMTAxMDAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJKdG5QZl1234567890
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789==
-----END CERTIFICATE-----"""
        
        self.cert2 = """-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDKVaBh8W8+5jANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNDEyMTAxMDAwMDBaFw0yNTEyMTAxMDAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJKdG5QZl9876543210
zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA0987654321==
-----END CERTIFICATE-----"""
    
    def build_vso(self, suboptions):
        """Build Vendor-Specific Option (Option 17)"""
        vso_data = struct.pack('!I', self.enterprise)  # Enterprise number
        
        for code, value in suboptions:
            if isinstance(value, str):
                value = value.encode('utf-8')
            vso_data += struct.pack('!HH', code, len(value)) + value
        
        return vso_data
    
    def send_advertise(self, client_packet, client_addr):
        """Send Advertise message with VSO containing sub-option 90"""
        print(f"Sending Advertise to {client_addr}")
        
        # Extract transaction ID
        xid = client_packet[DHCP6_Solicit].trid
        
        # Build VSO with sub-option 90 (gate requirement)
        vso_data = self.build_vso([(90, b"gate_passed")])
        
        # Create Advertise packet
        packet = IPv6(dst=client_addr, src="fe80::1") / \
                UDP(sport=547, dport=546) / \
                DHCP6_Advertise(trid=xid) / \
                DHCP6OptServerId(duid=self.server_duid) / \
                DHCP6OptVendorSpecificInfo(enterprisenum=self.enterprise, vso=vso_data)
        
        send(packet, iface=self.interface, verbose=False)
        print(f"Sent Advertise with VSO (enterprise={self.enterprise})")
    
    def send_reply(self, client_packet, client_addr):
        """Send Reply message with VSO containing certificate chain (sub-option 77)"""
        print(f"Sending Reply to {client_addr}")
        
        # Extract transaction ID
        xid = client_packet[DHCP6_Request].trid
        
        # Build certificate chain for sub-option 77
        cert_chain = f"{self.cert1} {self.cert2}"
        
        # Build VSO with sub-option 77 (certificate reply)
        vso_data = self.build_vso([(77, cert_chain)])
        
        # Create Reply packet
        packet = IPv6(dst=client_addr, src="fe80::1") / \
                UDP(sport=547, dport=546) / \
                DHCP6_Reply(trid=xid) / \
                DHCP6OptServerId(duid=self.server_duid) / \
                DHCP6OptVendorSpecificInfo(enterprisenum=self.enterprise, vso=vso_data)
        
        send(packet, iface=self.interface, verbose=False)
        print(f"Sent Reply with certificate chain ({len(cert_chain)} bytes)")
    
    def packet_handler(self, packet):
        """Handle incoming DHCPv6 packets"""
        if not packet.haslayer(IPv6) or not packet.haslayer(UDP):
            return
        
        if packet[UDP].dport != 547:  # DHCPv6 server port
            return
        
        client_addr = packet[IPv6].src
        
        try:
            if packet.haslayer(DHCP6_Solicit):
                print(f"Received Solicit from {client_addr}")
                time.sleep(0.1)  # Small delay to simulate processing
                self.send_advertise(packet, client_addr)
                
            elif packet.haslayer(DHCP6_Request):
                print(f"Received Request from {client_addr}")
                time.sleep(0.1)
                self.send_reply(packet, client_addr)
                
        except Exception as e:
            print(f"Error handling packet: {e}")
    
    def start(self):
        """Start the fake server"""
        print(f"Starting fake DHCPv6 server on {self.interface}")
        print(f"Enterprise number: {self.enterprise}")
        print("Listening for DHCPv6 packets...")
        
        # Filter for DHCPv6 packets
        filter_str = "udp and port 547"
        
        try:
            sniff(iface=self.interface, filter=filter_str, prn=self.packet_handler)
        except KeyboardInterrupt:
            print("\nServer stopped by user")
        except Exception as e:
            print(f"Error: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 fake_dhcp6_server.py <interface> [enterprise_number]")
        print("Example: python3 fake_dhcp6_server.py eth0 99999")
        sys.exit(1)
    
    interface = sys.argv[1]
    enterprise = int(sys.argv[2]) if len(sys.argv) > 2 else 99999
    
    server = FakeDHCPv6Server(interface, enterprise)
    server.start()

if __name__ == "__main__":
    main()