#ifndef DHCP6_VENDOR_H
#define DHCP6_VENDOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "cfg.h"

#define DHCPv6_OPTION_VENDOR_OPTS 17

// VSO TLV operations
int vso_append_subopt(uint8_t *buf, size_t cap, size_t *pos,
                      uint16_t code, const uint8_t *value, uint16_t value_len);

// Core functionality
int build_request_vso(const app_cfg_t *cfg, uint8_t *out, size_t cap, size_t *used);
bool check_advertise_gate(const app_cfg_t *cfg, const uint8_t *pkt, size_t len);
int parse_reply_77_and_save(const app_cfg_t *cfg, const uint8_t *vso, size_t vso_len);

// Packet parsing helpers
const uint8_t *find_dhcp6_option(const uint8_t *pkt, size_t len, uint16_t option_code, uint16_t *option_len);
const uint8_t *find_vso_subopt(const uint8_t *vso_data, size_t vso_len, 
                               uint32_t enterprise, uint16_t subopt_code, uint16_t *subopt_len);

// PEM validation
bool is_valid_pem_cert(const char *pem_str);
int split_pem_chain(const char *chain_str, char **cert1, char **cert2);

#endif // DHCP6_VENDOR_H