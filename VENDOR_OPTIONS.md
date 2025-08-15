# DHCPv6 Vendor-Specific Options Integration

This document describes the integration of DHCPv6 vendor-specific options (VSO) support into ISC DHCP.

## Overview

The vendor-specific options integration adds support for RFC 3315 Option 17 (Vendor-Specific Information) with cryptographic capabilities including RSA signing, certificate exchange, and PEM certificate handling.

## Features

- **DHCPv6 VSO Processing**: Full support for parsing and generating vendor-specific options
- **Cryptographic Security**: RSA-2048/SHA-256 signatures, Base64 encoding, PEM certificates
- **Modular Design**: Separate libraries for crypto utilities and vendor option processing
- **Enterprise Support**: Configurable enterprise-specific handlers
- **Server Integration**: Seamless integration with existing DHCPv6 server functionality

## Build Requirements

### Dependencies

- **OpenSSL**: Required for cryptographic operations
  - Ubuntu/Debian: `sudo apt-get install libssl-dev`
  - CentOS/RHEL: `sudo yum install openssl-devel`
  - macOS: `brew install openssl`

### Build Configuration

```bash
# Configure with vendor options enabled
./configure --enable-vendor-options

# If OpenSSL is in a custom location
./configure --enable-vendor-options --with-openssl=/path/to/openssl

# Build
make clean && make
```

## File Structure

### Core Components

```
common/
├── crypto_utils.c          # Cryptographic utilities implementation
├── vendor_options.c        # VSO processing implementation

includes/
├── crypto_utils.h          # Crypto function declarations
├── vendor_options.h        # VSO processing declarations

server/
├── vendor_handler.c        # Server-side VSO request handler
├── dhcpv6.c               # Modified to include VSO processing
├── dhcpd.c                # Modified for vendor handler initialization
```

### Example Configurations

```
doc/examples/
├── dhcpd-vendor-options.conf    # Server configuration example
```

## Architecture

### Data Flow

1. **Client Request**: DHCPv6 client sends request with VSO (Option 17)
2. **VSO Extraction**: Server extracts and parses vendor-specific sub-options
3. **Validation**: Signature verification using client certificates
4. **Processing**: Enterprise-specific handler processes the request
5. **Response Generation**: Server generates VSO response with certificates
6. **Client Processing**: Client receives and stores server certificates

### Key Components

#### Crypto Utils (`crypto_utils.c/h`)
- RSA key management and operations
- SHA-256 signature creation/verification
- Base64 encoding/decoding
- PEM certificate handling
- Secure memory operations

#### Vendor Options (`vendor_options.c/h`)
- VSO packet parsing and building
- Sub-option management
- Enterprise handler registration
- DHCPv6 packet integration

#### Vendor Handler (`vendor_handler.c`)
- Server-side VSO request processing
- Certificate validation and storage
- Enterprise-specific logic implementation
- Response generation

## Configuration

### Server Configuration (Future Implementation)

```apache
# Enable vendor options for enterprise 12345
vendor-config enterprise-12345 {
    enabled true;
    auto-respond true;
    
    # Cryptographic settings
    private-key "/etc/dhcp/vendor/server.key";
    certificate-chain "/etc/dhcp/vendor/cert_chain.pem";
    require-signature true;
    
    # Sub-option configuration
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
        save-path "/var/lib/dhcp/client-certs/";
    }
    
    sub-option 77 {
        type "certificate-chain";
        certificate-chain "/etc/dhcp/vendor/response_chain.pem";
    }
}

# Host-specific vendor configuration
host vendor-client-001 {
    hardware ethernet 00:11:22:33:44:55;
    vendor-config enterprise-12345;
    vendor-serial-number "ABC123456789";
}
```

### Standard Sub-option Codes

- **71**: Serial Number (client → server)
- **72**: RSA-SHA256 Signature (client → server)  
- **73**: Client Certificate Request (client → server)
- **74**: Duplicate Signature (client → server)
- **77**: Server Certificate Chain (server → client)

## Testing

### Build Test

```bash
# Run the integrated build test
./test_vendor_build.sh
```

### Manual Testing

```bash
# 1. Create test keys and certificates
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key server.key -out server.pem -days 365

# 2. Test server startup
sudo ./server/dhcpd -6 -f -cf doc/examples/dhcpd-vendor-options.conf

# 3. Monitor logs for vendor option initialization
tail -f /var/log/syslog | grep vendor
```

## Security Considerations

### Key Management
- Private keys must have 0600 permissions
- Certificate files should have 0644 permissions
- Sensitive data is cleared from memory after use

### Validation
- All input data is length-validated
- PEM certificate format verification
- RSA signature verification using client certificates
- Base64 decoding with overflow protection

### File Operations
- Secure file permissions verification
- Atomic certificate file writes
- Directory creation with proper permissions

## Implementation Status

### Completed ✅
- ✅ Core crypto utilities library (`crypto_utils.c/h`)
- ✅ Vendor options processing library (`vendor_options.c/h`)
- ✅ Build system integration (autoconf/automake)
- ✅ Server-side VSO handling (`vendor_handler.c`)
- ✅ DHCPv6 server integration (`dhcpv6.c` modifications)
- ✅ Client-side VSO processing (`vendor_client.c`)
- ✅ DHCPv6 client integration (`dhc6.c` modifications)
- ✅ Configuration parser for vendor-config syntax
- ✅ Comprehensive unit tests for all components
- ✅ Build verification script (`test_vendor_build.sh`)
- ✅ Enterprise handler framework
- ✅ Complete configuration examples

### Integration Points
- **Lexer**: Added `vendor-config` keyword recognition in `conflex.c`
- **Parser**: Added `VENDOR_CONFIG` token and parsing logic in `confpars.c`
- **Server**: Integrated VSO handling in `dhcpv6.c:lease_to_client()`
- **Client**: Integrated VSO generation in `dhc6.c:make_client6_options()`
- **Client**: Integrated VSO processing in `dhc6.c:dhc6_leaseify()`

## API Reference

### Crypto Utilities

```c
// Initialize crypto subsystem
int crypto_utils_init(void);

// RSA operations
int crypto_rsa_sign_sha256(crypto_rsa_key_t *private_key,
                          const unsigned char *data, size_t data_len,
                          unsigned char *signature, size_t *sig_len);

int crypto_rsa_verify_sha256(crypto_rsa_key_t *public_key,
                            const unsigned char *data, size_t data_len,
                            const unsigned char *signature, size_t sig_len);

// Base64 operations
char *crypto_base64_encode(const unsigned char *data, size_t len);
int crypto_base64_decode(const char *encoded, unsigned char **decoded, size_t *decoded_len);

// Certificate operations  
int crypto_load_pem_certificate(const char *path, struct data_string *cert);
int crypto_save_pem_certificate(const char *path, const struct data_string *cert, mode_t mode);
```

### Vendor Options

```c
// Initialize vendor options subsystem
int vendor_options_init(void);

// VSO processing
int vendor_parse_option(const struct data_string *vso_data,
                       struct vendor_option *parsed_vso);

int vendor_build_option(const struct vendor_option *vso,
                       struct data_string *result);

// Sub-option management
int vendor_add_sub_option(struct vendor_option *vso,
                         uint16_t code, const unsigned char *data, uint16_t length);

const struct vendor_sub_option *vendor_find_sub_option(const struct vendor_option *vso,
                                                       uint16_t code);

// Server integration
int vendor_handle_request(struct packet *packet,
                         struct option_state *options,
                         struct option_state *reply_options);
```

## Troubleshooting

### Build Issues

**Error**: `OpenSSL headers not found`
- **Solution**: Install OpenSSL development packages and use `--with-openssl=/path`

**Error**: `vendor_handle_request undefined`
- **Solution**: Ensure `--enable-vendor-options` was used during configure

### Runtime Issues

**Error**: `Failed to initialize vendor options handler`
- **Solution**: Check OpenSSL installation and file permissions

**Error**: `Signature verification failed`
- **Solution**: Verify certificate format and key pair matching

### Debug Mode

```bash
# Enable debug logging
sudo ./server/dhcpd -6 -f -d -cf dhcpd.conf

# Check for vendor option messages
grep -i vendor /var/log/syslog
```

## Contributing

### Code Style
- Follow existing ISC DHCP coding standards
- Use ISC memory management functions (dmalloc/dfree)
- Include error handling and logging
- Document public APIs

### Testing
- Add unit tests for new functions
- Test with various enterprise numbers
- Verify memory leak prevention
- Test error conditions

## License

This vendor options integration follows the same Mozilla Public License 2.0 as ISC DHCP.

## Support

For issues specific to the vendor options integration:
1. Check the build test script output
2. Verify OpenSSL installation and configuration  
3. Review log files for vendor-specific messages
4. Test with the provided example configurations