#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>

#include "cfg.h"
#include "log.h"
#include "crypto.h"
#include "dhcp6_vendor.h"

#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547
#define DHCPV6_MULTICAST_ADDR "ff02::1:2"

// Exit codes
#define EXIT_SUCCESS_CODE    0
#define EXIT_NETWORK_TIMEOUT 2
#define EXIT_CONFIG_ERROR    3
#define EXIT_CRYPTO_ERROR    4
#define EXIT_REPLY_ERROR     5
#define EXIT_GATE_REJECTED   10

// DHCPv6 message types
#define DHCPV6_SOLICIT     1
#define DHCPV6_ADVERTISE   2
#define DHCPV6_REQUEST     3
#define DHCPV6_REPLY       7

typedef struct {
    uint8_t msg_type;
    uint8_t transaction_id[3];
    uint8_t options[];
} __attribute__((packed)) dhcpv6_msg_t;

typedef struct {
    uint16_t code;
    uint16_t length;
    uint8_t data[];
} __attribute__((packed)) dhcpv6_option_t;

static volatile int running = 1;
static app_cfg_t config;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

static void usage(const char *progname) {
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("DHCPv6 Vendor Client\n\n");
    printf("Options:\n");
    printf("  -c, --config FILE    Configuration file (default: /etc/vendor/dhcp6-vendor.conf)\n");
    printf("  -i, --iface IFACE    Network interface\n");
    printf("  -d, --dry-run        Don't send packets, just show what would be sent\n");
    printf("  -v, --verbose        Verbose output (debug level)\n");
    printf("  -h, --help           Show this help\n");
}

static uint32_t generate_transaction_id(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)(tv.tv_sec ^ tv.tv_usec);
}

static int create_dhcp6_socket(const char *interface) {
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_error("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_warn("Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    // Bind to interface if specified
    if (interface) {
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0) {
            log_error("Failed to bind to interface %s: %s", interface, strerror(errno));
            close(sock);
            return -1;
        }
        log_info("Bound to interface %s", interface);
    }
    
    // Bind to DHCPv6 client port
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(DHCPV6_CLIENT_PORT);
    addr.sin6_addr = in6addr_any;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Failed to bind to port %d: %s", DHCPV6_CLIENT_PORT, strerror(errno));
        close(sock);
        return -1;
    }
    
    log_debug("DHCPv6 socket created and bound");
    return sock;
}

static int send_solicit(int sock, uint32_t xid) {
    uint8_t packet[1024];
    size_t pos = 0;
    
    // DHCPv6 header
    dhcpv6_msg_t *msg = (dhcpv6_msg_t*)packet;
    msg->msg_type = DHCPV6_SOLICIT;
    msg->transaction_id[0] = (xid >> 16) & 0xff;
    msg->transaction_id[1] = (xid >> 8) & 0xff;
    msg->transaction_id[2] = xid & 0xff;
    pos += sizeof(dhcpv6_msg_t);
    
    // Add Client Identifier option (Option 1) - simplified DUID-LL
    dhcpv6_option_t *opt = (dhcpv6_option_t*)(packet + pos);
    opt->code = htons(1); // Client ID
    opt->length = htons(10); // DUID-LL: type(2) + hw_type(2) + 6 bytes MAC
    pos += sizeof(dhcpv6_option_t);
    
    // DUID-LL format: type=3, hw_type=1 (Ethernet), MAC address
    uint8_t duid[] = {0x00, 0x03, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(packet + pos, duid, sizeof(duid));
    pos += sizeof(duid);
    
    // Send to multicast address
    struct sockaddr_in6 dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DHCPV6_SERVER_PORT);
    inet_pton(AF_INET6, DHCPV6_MULTICAST_ADDR, &dest.sin6_addr);
    
    ssize_t sent = sendto(sock, packet, pos, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (sent < 0) {
        log_error("Failed to send Solicit: %s", strerror(errno));
        return -1;
    }
    
    log_info("Sent Solicit message (transaction ID: %06x, %zu bytes)", xid, pos);
    log_hex_dump("Solicit packet", packet, pos);
    
    return 0;
}

static int send_request(int sock, uint32_t xid, const uint8_t *server_id, size_t server_id_len) {
    uint8_t packet[4096];
    size_t pos = 0;
    
    // DHCPv6 header
    dhcpv6_msg_t *msg = (dhcpv6_msg_t*)packet;
    msg->msg_type = DHCPV6_REQUEST;
    msg->transaction_id[0] = (xid >> 16) & 0xff;
    msg->transaction_id[1] = (xid >> 8) & 0xff;
    msg->transaction_id[2] = xid & 0xff;
    pos += sizeof(dhcpv6_msg_t);
    
    // Client ID (same as in Solicit)
    dhcpv6_option_t *opt = (dhcpv6_option_t*)(packet + pos);
    opt->code = htons(1);
    opt->length = htons(10);
    pos += sizeof(dhcpv6_option_t);
    
    uint8_t duid[] = {0x00, 0x03, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(packet + pos, duid, sizeof(duid));
    pos += sizeof(duid);
    
    // Server ID (from Advertise)
    if (server_id && server_id_len > 0) {
        opt = (dhcpv6_option_t*)(packet + pos);
        opt->code = htons(2); // Server ID
        opt->length = htons(server_id_len);
        pos += sizeof(dhcpv6_option_t);
        
        memcpy(packet + pos, server_id, server_id_len);
        pos += server_id_len;
    }
    
    // Add VSO (Option 17)
    uint8_t vso_data[2048];
    size_t vso_len;
    
    if (build_request_vso(&config, vso_data, sizeof(vso_data), &vso_len) != 0) {
        log_error("Failed to build VSO for Request");
        return -1;
    }
    
    opt = (dhcpv6_option_t*)(packet + pos);
    opt->code = htons(17); // Vendor-specific Information
    opt->length = htons(vso_len);
    pos += sizeof(dhcpv6_option_t);
    
    memcpy(packet + pos, vso_data, vso_len);
    pos += vso_len;
    
    // Send to multicast address (or unicast if we have server address)
    struct sockaddr_in6 dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DHCPV6_SERVER_PORT);
    inet_pton(AF_INET6, DHCPV6_MULTICAST_ADDR, &dest.sin6_addr);
    
    ssize_t sent = sendto(sock, packet, pos, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (sent < 0) {
        log_error("Failed to send Request: %s", strerror(errno));
        return -1;
    }
    
    log_info("Sent Request message with VSO (transaction ID: %06x, %zu bytes)", xid, pos);
    log_hex_dump("Request packet", packet, pos);
    
    return 0;
}

static int wait_for_message(int sock, uint8_t expected_type, uint32_t xid,
                           uint8_t *buffer, size_t buffer_size, int timeout_sec) {
    fd_set readfds;
    struct timeval timeout;
    
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    
    int ret = select(sock + 1, &readfds, NULL, NULL, &timeout);
    if (ret < 0) {
        log_error("select() failed: %s", strerror(errno));
        return -1;
    }
    
    if (ret == 0) {
        log_warn("Timeout waiting for %s message", 
                expected_type == DHCPV6_ADVERTISE ? "Advertise" : "Reply");
        return -2;
    }
    
    struct sockaddr_in6 from;
    socklen_t from_len = sizeof(from);
    
    ssize_t received = recvfrom(sock, buffer, buffer_size, 0,
                               (struct sockaddr*)&from, &from_len);
    if (received < 0) {
        log_error("recvfrom() failed: %s", strerror(errno));
        return -1;
    }
    
    if (received < (ssize_t)sizeof(dhcpv6_msg_t)) {
        log_warn("Received packet too small");
        return -1;
    }
    
    dhcpv6_msg_t *msg = (dhcpv6_msg_t*)buffer;
    uint32_t recv_xid = (msg->transaction_id[0] << 16) |
                        (msg->transaction_id[1] << 8) |
                        msg->transaction_id[2];
    
    if (msg->msg_type != expected_type) {
        log_debug("Received message type %u, expected %u", msg->msg_type, expected_type);
        return 0; // Not the message we want, but not an error
    }
    
    if (recv_xid != xid) {
        log_debug("Received transaction ID %06x, expected %06x", recv_xid, xid);
        return 0; // Not our transaction
    }
    
    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &from.sin6_addr, addr_str, sizeof(addr_str));
    log_info("Received %s from %s (%zd bytes)", 
             expected_type == DHCPV6_ADVERTISE ? "Advertise" : "Reply",
             addr_str, received);
    
    log_hex_dump("Received packet", buffer, received);
    
    return (int)received;
}

int main(int argc, char *argv[]) {
    const char *config_file = "/etc/vendor/dhcp6-vendor.conf";
    const char *interface = NULL;
    int dry_run = 0;
    int verbose = 0;
    
    static struct option long_options[] = {
        {"config",  required_argument, 0, 'c'},
        {"iface",   required_argument, 0, 'i'},
        {"dry-run", no_argument,       0, 'd'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "c:i:dvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'i':
                interface = optarg;
                break;
            case 'd':
                dry_run = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS_CODE);
            default:
                usage(argv[0]);
                exit(EXIT_CONFIG_ERROR);
        }
    }
    
    // Initialize subsystems
    if (crypto_init() != 0) {
        fprintf(stderr, "Failed to initialize crypto\n");
        exit(EXIT_CRYPTO_ERROR);
    }
    
    // Load configuration
    if (cfg_load(config_file, &config) != 0) {
        fprintf(stderr, "Failed to load configuration from %s\n", config_file);
        exit(EXIT_CONFIG_ERROR);
    }
    
    // Override interface if specified
    if (interface) {
        free(config.dhcp6.iface);
        config.dhcp6.iface = strdup(interface);
    }
    
    // Initialize logging
    if (log_init(config.logging.path, verbose ? "debug" : config.logging.level,
                config.logging.hex_dump || verbose) != 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        exit(EXIT_CONFIG_ERROR);
    }
    
    log_info("DHCPv6 Vendor Client starting");
    log_info("Interface: %s", config.dhcp6.iface);
    log_info("Enterprise: %u", config.vendor.enterprise);
    
    // Validate configuration
    if (cfg_validate(&config) != 0) {
        log_error("Configuration validation failed");
        exit(EXIT_CONFIG_ERROR);
    }
    
    if (dry_run) {
        log_info("Dry run mode - testing VSO generation");
        uint8_t vso_data[2048];
        size_t vso_len;
        
        if (build_request_vso(&config, vso_data, sizeof(vso_data), &vso_len) == 0) {
            log_info("Successfully generated VSO (%zu bytes)", vso_len);
            log_hex_dump("VSO data", vso_data, vso_len);
            printf("Dry run successful - VSO generation works\n");
        } else {
            printf("Dry run failed - VSO generation error\n");
            exit(EXIT_CRYPTO_ERROR);
        }
        
        cfg_free(&config);
        crypto_cleanup();
        log_cleanup();
        exit(EXIT_SUCCESS_CODE);
    }
    
    // Set up signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create socket
    int sock = create_dhcp6_socket(config.dhcp6.iface);
    if (sock < 0) {
        exit(EXIT_NETWORK_TIMEOUT);
    }
    
    uint32_t transaction_id = generate_transaction_id() & 0xffffff;
    log_info("Using transaction ID: %06x", transaction_id);
    
    // Send Solicit
    if (send_solicit(sock, transaction_id) != 0) {
        close(sock);
        exit(EXIT_NETWORK_TIMEOUT);
    }
    
    // Wait for Advertise
    uint8_t packet_buffer[4096];
    int advertise_len = wait_for_message(sock, DHCPV6_ADVERTISE, transaction_id,
                                        packet_buffer, sizeof(packet_buffer),
                                        config.dhcp6.timeout_seconds);
    
    if (advertise_len <= 0) {
        log_error("Failed to receive Advertise message");
        close(sock);
        exit(EXIT_NETWORK_TIMEOUT);
    }
    
    // Check Advertise gate
    if (!check_advertise_gate(&config, packet_buffer, advertise_len)) {
        log_error("Advertise message failed gate check");
        close(sock);
        exit(EXIT_GATE_REJECTED);
    }
    
    // Extract Server ID from Advertise
    uint16_t server_id_len;
    const uint8_t *server_id = find_dhcp6_option(packet_buffer, advertise_len, 2, &server_id_len);
    
    // Send Request
    if (send_request(sock, transaction_id, server_id, server_id_len) != 0) {
        close(sock);
        exit(EXIT_NETWORK_TIMEOUT);
    }
    
    // Wait for Reply
    int reply_len = wait_for_message(sock, DHCPV6_REPLY, transaction_id,
                                    packet_buffer, sizeof(packet_buffer),
                                    config.dhcp6.timeout_seconds);
    
    if (reply_len <= 0) {
        log_error("Failed to receive Reply message");
        close(sock);
        exit(EXIT_NETWORK_TIMEOUT);
    }
    
    // Process Reply VSO
    uint16_t vso_len;
    const uint8_t *vso_data = find_dhcp6_option(packet_buffer, reply_len, 17, &vso_len);
    
    if (!vso_data) {
        log_error("No VSO found in Reply message");
        close(sock);
        exit(EXIT_REPLY_ERROR);
    }
    
    if (parse_reply_77_and_save(&config, vso_data, vso_len) != 0) {
        log_error("Failed to parse and save certificate chain from Reply");
        close(sock);
        exit(EXIT_REPLY_ERROR);
    }
    
    log_info("Successfully completed DHCPv6 vendor exchange");
    
    // Cleanup
    close(sock);
    cfg_free(&config);
    crypto_cleanup();
    log_cleanup();
    
    return EXIT_SUCCESS_CODE;
}