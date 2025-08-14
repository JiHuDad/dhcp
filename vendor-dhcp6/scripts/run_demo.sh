#!/bin/bash
# Demo script for DHCPv6 vendor client

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "DHCPv6 Vendor Client Demo"
echo "========================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This demo requires root privileges for network operations."
   echo "Please run with sudo: sudo $0"
   exit 1
fi

# Setup
echo "1. Setting up directories and certificates..."
cd "$PROJECT_DIR"
./scripts/mkdirs.sh
./scripts/gen_keypair.sh

# Set SN_NUMBER environment variable
export SN_NUMBER="DEMO123456789"
echo "2. Set SN_NUMBER = $SN_NUMBER"

# Build the client
echo "3. Building vendor client..."
make clean
make -j

# Test dry run first
echo "4. Testing dry run mode..."
./vendor-dhclient --config ./conf/vendor-dhcp6.toml --dry-run --verbose

echo ""
echo "5. Starting demo with fake server..."
echo "   This will use loopback interface for testing"

# Update config for loopback
cp ./conf/vendor-dhcp6.toml /tmp/demo-config.toml
sed -i 's/iface = "eth0"/iface = "lo"/' /tmp/demo-config.toml

# Check if Python and scapy are available
if ! python3 -c "import scapy" 2>/dev/null; then
    echo "Warning: Python scapy not available. Skipping fake server demo."
    echo "To install scapy: pip3 install scapy"
    echo ""
    echo "Demo completed successfully (dry run only)!"
    exit 0
fi

# Start fake server in background
echo "Starting fake DHCPv6 server..."
python3 ./tests/it/fake_dhcp6_server.py lo 99999 &
SERVER_PID=$!

# Wait a moment for server to start
sleep 2

# Run client
echo "Running vendor client..."
timeout 30 ./vendor-dhclient --config /tmp/demo-config.toml --iface lo --verbose || {
    echo "Client finished (timeout or completion)"
}

# Stop fake server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "6. Checking results..."

# Check if certificates were saved
if [[ -f /var/lib/vendor-dhcp6/server0.pem ]] && [[ -f /var/lib/vendor-dhcp6/server1.pem ]]; then
    echo "✓ Certificates saved successfully:"
    echo "  - $(wc -c < /var/lib/vendor-dhcp6/server0.pem) bytes in server0.pem"
    echo "  - $(wc -c < /var/lib/vendor-dhcp6/server1.pem) bytes in server1.pem"
    
    if [[ -f /var/lib/vendor-dhcp6/server_chain.pem ]]; then
        echo "  - $(wc -c < /var/lib/vendor-dhcp6/server_chain.pem) bytes in server_chain.pem"
    fi
    
    echo ""
    echo "Certificate contents preview:"
    head -3 /var/lib/vendor-dhcp6/server0.pem
    echo "..."
    
else
    echo "⚠ Certificates not found - check logs for errors"
fi

# Show log file
if [[ -f /var/log/vendor-dhcp6.log ]]; then
    echo ""
    echo "Recent log entries:"
    tail -10 /var/log/vendor-dhcp6.log
fi

echo ""
echo "Demo completed!"
echo "Check /var/log/vendor-dhcp6.log for detailed logs"
echo "Cleanup: rm -rf /var/lib/vendor-dhcp6/* /etc/vendor/* /var/log/vendor-dhcp6.log"