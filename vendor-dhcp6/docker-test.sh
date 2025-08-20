#!/bin/bash
#
# Docker-based DHCPv6 Vendor Client Test Script
# Provides easy commands to test the vendor client in isolated environment
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
DHCPv6 Vendor Client Docker Test Tool

Usage: $0 <command> [options]

Commands:
    build           - Build Docker images
    test            - Run automated test (server + client)
    interactive     - Start interactive test environment
    server          - Start fake DHCPv6 server only
    client          - Run client against running server
    dry-run         - Test VSO generation without network
    logs            - Show container logs
    cleanup         - Stop and remove containers
    shell           - Get shell in test environment
    monitor         - Monitor network traffic
    help            - Show this help

Examples:
    $0 build                    # Build images
    $0 test                     # Full automated test
    $0 interactive              # Manual testing environment
    $0 client                   # Run client only
    $0 shell                    # Get interactive shell
    $0 monitor                  # Monitor DHCPv6 traffic

Prerequisites:
    - Docker and docker-compose installed
    - Sufficient permissions for privileged containers

EOF
}

# Build Docker images
build_images() {
    log_info "Building Docker images..."
    docker-compose build
    log_success "Docker images built successfully"
}

# Run automated test
run_automated_test() {
    log_info "Starting automated DHCPv6 vendor test..."
    
    # Clean up any existing containers
    docker-compose down 2>/dev/null || true
    
    # Clear previous logs
    rm -rf tests/logs/* tests/output/* 2>/dev/null || true
    
    log_info "Starting server and client..."
    docker-compose up --abort-on-container-exit
    
    log_info "Test completed. Checking results..."
    
    # Check if certificates were generated
    if [[ -f "tests/output/server0.pem" ]] && [[ -f "tests/output/server1.pem" ]]; then
        log_success "Certificates successfully received and saved!"
        echo "Certificate files:"
        ls -la tests/output/*.pem 2>/dev/null || true
    else
        log_warn "Certificates not found in output directory"
    fi
    
    # Show logs
    echo
    log_info "Container logs:"
    docker-compose logs
}

# Start interactive environment
start_interactive() {
    log_info "Starting interactive test environment..."
    
    docker-compose down 2>/dev/null || true
    
    log_info "Starting all services in background..."
    docker-compose up -d
    
    log_success "Environment ready!"
    echo
    echo "Available containers:"
    echo "  dhcp6-server  - Fake DHCPv6 server"
    echo "  dhcp6-client  - Vendor client"
    echo "  dhcp6-test    - Test runner with tools"
    echo
    echo "Commands:"
    echo "  $0 shell                    # Get shell in test container"
    echo "  $0 client                   # Run vendor client"
    echo "  $0 logs                     # Show logs"
    echo "  $0 monitor                  # Monitor traffic"
    echo "  $0 cleanup                  # Stop everything"
}

# Start server only
start_server() {
    log_info "Starting DHCPv6 fake server..."
    docker-compose up dhcp6-server
}

# Run client only
run_client() {
    log_info "Running DHCPv6 vendor client..."
    
    if ! docker-compose ps | grep -q "dhcp6-server.*Up"; then
        log_error "Server not running. Start with: $0 server"
        exit 1
    fi
    
    docker-compose run --rm dhcp6-client \
        /app/vendor-dhclient --config /etc/vendor/dhcp6-vendor.conf --iface eth0 -v
}

# Dry run test
run_dry_run() {
    log_info "Running dry-run test (VSO generation only)..."
    docker-compose run --rm dhcp6-client \
        /app/vendor-dhclient --config /etc/vendor/dhcp6-vendor.conf --dry-run
}

# Show logs
show_logs() {
    echo "=== Container Logs ==="
    docker-compose logs
    
    echo
    echo "=== Log Files ==="
    if [[ -d "tests/logs" ]]; then
        find tests/logs -name "*.log" -exec echo "=== {} ===" \; -exec cat {} \;
    else
        log_warn "No log files found"
    fi
}

# Get shell
get_shell() {
    log_info "Opening shell in test container..."
    docker-compose exec dhcp6-test /bin/bash
}

# Monitor network traffic
monitor_traffic() {
    log_info "Monitoring DHCPv6 traffic..."
    log_info "Press Ctrl+C to stop"
    
    docker-compose exec dhcp6-test \
        tcpdump -i eth0 -n -v port 546 or port 547
}

# Cleanup
cleanup() {
    log_info "Cleaning up Docker containers..."
    docker-compose down
    docker-compose rm -f 2>/dev/null || true
    log_success "Cleanup completed"
}

# Validate environment
validate_environment() {
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker not found. Please install Docker."
        exit 1
    fi
    
    if ! command -v docker-compose >/dev/null 2>&1; then
        log_error "docker-compose not found. Please install docker-compose."
        exit 1
    fi
    
    if [[ ! -f "vendor-dhclient" ]]; then
        log_error "vendor-dhclient binary not found. Run 'make' first."
        exit 1
    fi
}

# Main execution
main() {
    local command="${1:-help}"
    
    case "$command" in
        build)
            validate_environment
            build_images
            ;;
        test)
            validate_environment
            build_images
            run_automated_test
            ;;
        interactive)
            validate_environment
            build_images
            start_interactive
            ;;
        server)
            validate_environment
            start_server
            ;;
        client)
            validate_environment
            run_client
            ;;
        dry-run)
            validate_environment
            run_dry_run
            ;;
        logs)
            show_logs
            ;;
        shell)
            get_shell
            ;;
        monitor)
            monitor_traffic
            ;;
        cleanup)
            cleanup
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"