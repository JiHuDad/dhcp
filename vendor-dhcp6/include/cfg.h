#ifndef CFG_H
#define CFG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    struct {
        char *iface;
        char *duid_path;
        int timeout_seconds;
    } dhcp6;

    struct {
        uint32_t enterprise;
        char *sn_env;
        uint16_t code_sn;
        uint16_t code_sig;
        uint16_t code_cert_req;
        uint16_t code_sig_dup;
        uint16_t code_cert_reply;
    } vendor;

    struct {
        char *private_key;
        char *request_cert;
        char *reply_cert0;
        char *reply_cert1;
        char *reply_chain_bundle; // optional
    } paths;

    struct {
        bool enabled;
        bool require_vendor;
        int require_vendor_subopt; // -1 if disabled
    } advertise_gate;

    struct {
        char *path;
        char *level; // "info"|"debug"|"error"
        bool hex_dump;
    } logging;
} app_cfg_t;

int cfg_load(const char *path, app_cfg_t *out);
void cfg_free(app_cfg_t *cfg);
int cfg_validate(const app_cfg_t *cfg);

#endif // CFG_H