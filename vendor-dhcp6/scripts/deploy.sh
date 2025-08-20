#!/bin/bash
#
# Deployment script for DHCPv6 Vendor Client
# Handles installation, configuration, and systemd service setup
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="vendor-dhclient"
SERVICE_NAME="vendor-dhcp6"

# Default paths
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
CONFDIR="/etc/vendor"
SYSTEMD_DIR="/etc/systemd/system"
LOGDIR="/var/log"
STATEDIR="/var/lib/vendor-dhcp6"
KEYDIR="$CONFDIR/keys"
CERTDIR="$CONFDIR/certs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Create necessary directories with proper permissions
create_directories() {
    log_info "Creating directories..."
    
    install -d -m 755 "$BINDIR"
    install -d -m 750 "$CONFDIR"
    install -d -m 700 "$KEYDIR"
    install -d -m 755 "$CERTDIR"
    install -d -m 755 "$STATEDIR"
    install -d -m 755 "$LOGDIR"
    
    # Set ownership
    chown root:root "$CONFDIR" "$KEYDIR" "$CERTDIR"
    chown root:root "$STATEDIR"
    
    log_success "Directories created"
}

# Install binary
install_binary() {
    local binary_path="$PROJECT_ROOT/$BINARY_NAME"
    
    if [[ ! -f "$binary_path" ]]; then
        log_error "Binary not found: $binary_path"
        log_info "Run 'make' in $PROJECT_ROOT first"
        exit 1
    fi
    
    log_info "Installing binary..."
    install -m 755 "$binary_path" "$BINDIR/"
    log_success "Binary installed to $BINDIR/$BINARY_NAME"
}

# Install configuration
install_config() {
    local config_source="$PROJECT_ROOT/conf/vendor-dhcp6.toml"
    local config_dest="$CONFDIR/dhcp6-vendor.conf"
    
    if [[ ! -f "$config_source" ]]; then
        log_error "Configuration template not found: $config_source"
        exit 1
    fi
    
    log_info "Installing configuration..."
    
    if [[ -f "$config_dest" ]]; then
        local backup="$config_dest.backup.$(date +%Y%m%d_%H%M%S)"
        log_warn "Backing up existing config to $backup"
        cp "$config_dest" "$backup"
    fi
    
    install -m 640 "$config_source" "$config_dest"
    chown root:root "$config_dest"
    
    log_success "Configuration installed to $config_dest"
}

# Install systemd service
install_systemd_service() {
    local service_source="$PROJECT_ROOT/conf/systemd.service.sample"
    local service_dest="$SYSTEMD_DIR/${SERVICE_NAME}@.service"
    
    if [[ ! -f "$service_source" ]]; then
        log_error "Systemd service template not found: $service_source"
        exit 1
    fi
    
    log_info "Installing systemd service..."
    
    # Update paths in service file
    sed "s|/usr/local/bin/vendor-dhclient|$BINDIR/$BINARY_NAME|g" "$service_source" > "$service_dest"
    chmod 644 "$service_dest"
    
    systemctl daemon-reload
    
    log_success "Systemd service installed to $service_dest"
}

# Generate keys and certificates
generate_keys() {
    local private_key="$KEYDIR/client.key"
    local cert_file="$CERTDIR/request.pem"
    
    if [[ -f "$private_key" ]]; then
        log_warn "Private key already exists: $private_key"
        read -p "Regenerate? [y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    log_info "Generating RSA private key..."
    openssl genrsa -out "$private_key" 2048
    chmod 600 "$private_key"
    chown root:root "$private_key"
    
    log_info "Generating certificate request..."
    openssl req -new -x509 -key "$private_key" -out "$cert_file" -days 365 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=vendor-dhcp6-client"
    chmod 644 "$cert_file"
    chown root:root "$cert_file"
    
    log_success "Keys and certificates generated"
}

# Setup environment file
setup_environment() {
    local env_file="$CONFDIR/environment"
    
    if [[ -f "$env_file" ]]; then
        log_warn "Environment file already exists: $env_file"
        return 0
    fi
    
    log_info "Creating environment file..."
    
    cat > "$env_file" << 'EOF'
# DHCPv6 Vendor Client Environment Variables
# Set your serial number here
SN_NUMBER=

# Optional: Override logging level
# LOG_LEVEL=debug

# Optional: Override configuration file
# CONFIG_FILE=/etc/vendor/dhcp6-vendor.conf
EOF
    
    chmod 640 "$env_file"
    chown root:root "$env_file"
    
    log_success "Environment file created: $env_file"
    log_warn "Remember to set SN_NUMBER in $env_file"
}

# Configure for specific interface
configure_interface() {
    local interface="$1"
    
    if [[ -z "$interface" ]]; then
        log_error "Interface name required"
        return 1
    fi
    
    log_info "Configuring for interface: $interface"
    
    # Enable and start service
    systemctl enable "${SERVICE_NAME}@${interface}.service"
    
    log_success "Service enabled for interface $interface"
    log_info "Start with: systemctl start ${SERVICE_NAME}@${interface}.service"
}

# Validate installation
validate_installation() {
    log_info "Validating installation..."
    
    local errors=0
    
    # Check binary
    if [[ ! -x "$BINDIR/$BINARY_NAME" ]]; then
        log_error "Binary not found or not executable: $BINDIR/$BINARY_NAME"
        errors=$((errors + 1))
    fi
    
    # Check configuration
    if [[ ! -f "$CONFDIR/dhcp6-vendor.conf" ]]; then
        log_error "Configuration file not found: $CONFDIR/dhcp6-vendor.conf"
        errors=$((errors + 1))
    fi
    
    # Check private key
    if [[ ! -f "$KEYDIR/client.key" ]]; then
        log_error "Private key not found: $KEYDIR/client.key"
        errors=$((errors + 1))
    fi
    
    # Check systemd service
    if [[ ! -f "$SYSTEMD_DIR/${SERVICE_NAME}@.service" ]]; then
        log_error "Systemd service not found: $SYSTEMD_DIR/${SERVICE_NAME}@.service"
        errors=$((errors + 1))
    fi
    
    # Test configuration parsing
    if ! "$BINDIR/$BINARY_NAME" --help >/dev/null 2>&1; then
        log_error "Binary test failed"
        errors=$((errors + 1))
    fi
    
    if [[ $errors -eq 0 ]]; then
        log_success "Installation validation passed"
        return 0
    else
        log_error "Installation validation failed ($errors errors)"
        return 1
    fi
}

# Uninstall function
uninstall() {
    log_info "Uninstalling DHCPv6 Vendor Client..."
    
    # Stop and disable services
    for service in /etc/systemd/system/${SERVICE_NAME}@*.service; do
        if [[ -f "$service" ]]; then
            local instance=$(basename "$service" .service)
            systemctl stop "$instance" 2>/dev/null || true
            systemctl disable "$instance" 2>/dev/null || true
        fi
    done
    
    # Remove files
    rm -f "$BINDIR/$BINARY_NAME"
    rm -f "$SYSTEMD_DIR/${SERVICE_NAME}@.service"
    
    systemctl daemon-reload
    
    log_warn "Configuration and keys left in $CONFDIR"
    log_warn "Logs left in $LOGDIR"
    log_warn "State directory left in $STATEDIR"
    
    log_success "Uninstallation complete"
}

# Show status
show_status() {
    echo "DHCPv6 Vendor Client Status"
    echo "==========================="
    echo
    
    # Check installation
    if [[ -x "$BINDIR/$BINARY_NAME" ]]; then
        echo "Binary: ✓ Installed ($BINDIR/$BINARY_NAME)"
        "$BINDIR/$BINARY_NAME" --help | head -2
    else
        echo "Binary: ✗ Not installed"
    fi
    
    echo
    
    # Check configuration
    if [[ -f "$CONFDIR/dhcp6-vendor.conf" ]]; then
        echo "Config: ✓ Found ($CONFDIR/dhcp6-vendor.conf)"
    else
        echo "Config: ✗ Not found"
    fi
    
    # Check keys
    if [[ -f "$KEYDIR/client.key" ]]; then
        echo "Keys: ✓ Found ($KEYDIR/client.key)"
    else
        echo "Keys: ✗ Not found"
    fi
    
    echo
    
    # Check systemd services
    echo "Systemd Services:"
    for service in /etc/systemd/system/${SERVICE_NAME}@*.service; do
        if [[ -f "$service" ]]; then
            local instance=$(basename "$service" .service)
            local status=$(systemctl is-active "$instance" 2>/dev/null || echo "inactive")
            local enabled=$(systemctl is-enabled "$instance" 2>/dev/null || echo "disabled")
            echo "  $instance: $status ($enabled)"
        fi
    done
    
    if ! ls /etc/systemd/system/${SERVICE_NAME}@*.service >/dev/null 2>&1; then
        echo "  No instances configured"
    fi
}

# Usage information
usage() {
    cat << EOF
DHCPv6 Vendor Client Deployment Script

Usage: $0 <command> [options]

Commands:
    install                 - Full installation (default)
    uninstall              - Remove installation
    configure <interface>  - Configure for specific interface
    status                 - Show installation status
    validate               - Validate installation
    keys                   - Generate keys and certificates only
    help                   - Show this help

Options:
    --prefix PATH          - Installation prefix (default: /usr/local)
    --no-keys             - Skip key generation
    --no-systemd          - Skip systemd service installation

Examples:
    $0 install                    # Full installation
    $0 configure eth0             # Configure for eth0 interface
    $0 install --no-keys          # Install without generating keys
    $0 status                     # Show current status

Prerequisites:
    - Root privileges
    - OpenSSL tools
    - systemd (for service management)
    - Built binary in project directory

EOF
}

# Main execution
main() {
    local command="${1:-install}"
    local no_keys=false
    local no_systemd=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --prefix)
                PREFIX="$2"
                BINDIR="$PREFIX/bin"
                shift 2
                ;;
            --no-keys)
                no_keys=true
                shift
                ;;
            --no-systemd)
                no_systemd=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            install|uninstall|status|validate|keys|help)
                command="$1"
                shift
                ;;
            configure)
                command="configure"
                interface="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
    
    case "$command" in
        install)
            require_root
            echo "Installing DHCPv6 Vendor Client..."
            echo "================================="
            create_directories
            install_binary
            install_config
            if [[ "$no_systemd" != true ]]; then
                install_systemd_service
            fi
            if [[ "$no_keys" != true ]]; then
                generate_keys
            fi
            setup_environment
            validate_installation
            echo
            log_success "Installation complete!"
            echo
            echo "Next steps:"
            echo "1. Edit $CONFDIR/environment and set SN_NUMBER"
            echo "2. Configure for interface: $0 configure <interface>"
            echo "3. Start service: systemctl start ${SERVICE_NAME}@<interface>"
            ;;
        uninstall)
            require_root
            uninstall
            ;;
        configure)
            require_root
            if [[ -z "$interface" ]]; then
                log_error "Interface name required"
                echo "Usage: $0 configure <interface>"
                exit 1
            fi
            configure_interface "$interface"
            ;;
        status)
            show_status
            ;;
        validate)
            validate_installation
            ;;
        keys)
            require_root
            create_directories
            generate_keys
            ;;
        help)
            usage
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"