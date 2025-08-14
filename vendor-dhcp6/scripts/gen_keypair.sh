#!/bin/bash
# Generate RSA key pair and test certificate for DHCPv6 vendor client

set -e

KEY_PATH="/etc/vendor/keys/client.key"
CERT_PATH="/etc/vendor/certs/request.pem"

echo "Generating RSA-2048 private key and test certificate..."

# Ensure directories exist
./scripts/mkdirs.sh

# Generate private key (RSA-2048)
openssl genrsa -out "$KEY_PATH" 2048
chmod 600 "$KEY_PATH"
echo "Private key saved to: $KEY_PATH"

# Generate self-signed certificate for testing
openssl req -new -x509 -key "$KEY_PATH" -out "$CERT_PATH" -days 365 -subj "/CN=DHCPv6-Vendor-Client/O=Test/C=US"
chmod 644 "$CERT_PATH"
echo "Test certificate saved to: $CERT_PATH"

# Show certificate info
echo ""
echo "Certificate info:"
openssl x509 -in "$CERT_PATH" -text -noout | head -20

echo ""
echo "Key and certificate generation completed successfully!"
echo "Private key: $KEY_PATH (mode 600)"
echo "Certificate: $CERT_PATH (mode 644)"