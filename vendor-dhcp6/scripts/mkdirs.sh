#!/bin/bash
# Create necessary directories with proper permissions

set -e

echo "Creating vendor DHCPv6 directories..."

# Create main directories
sudo mkdir -p /var/lib/vendor-dhcp6
sudo mkdir -p /etc/vendor/keys
sudo mkdir -p /etc/vendor/certs
sudo mkdir -p /var/log

# Set permissions
sudo chmod 750 /var/lib/vendor-dhcp6
sudo chmod 700 /etc/vendor/keys
sudo chmod 755 /etc/vendor/certs
sudo chmod 755 /var/log

# Change ownership to current user for development
sudo chown $USER:$USER /var/lib/vendor-dhcp6
sudo chown $USER:$USER /etc/vendor/keys
sudo chown $USER:$USER /etc/vendor/certs

echo "Directories created successfully:"
echo "  /var/lib/vendor-dhcp6 (750) - for DUID and received certificates"
echo "  /etc/vendor/keys (700) - for private keys"
echo "  /etc/vendor/certs (755) - for certificates"
echo "  /var/log (755) - for log files"

# Check if directories exist and show their permissions
ls -ld /var/lib/vendor-dhcp6 /etc/vendor/keys /etc/vendor/certs 2>/dev/null || true