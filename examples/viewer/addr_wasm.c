/* For the browser: core/address.c as is, turning a scriptPubKey into an address string */
#include "address.h"

static uint8_t spk[128];
static char out[ADDRESS_MAX];

__attribute__((export_name("addr_input"))) uint8_t *addr_input(void) {
    return spk;
}
__attribute__((export_name("addr_output"))) char *addr_output(void) {
    return out;
}
/* 1 on success; testnet is 0 or 1 */
__attribute__((export_name("addr_encode"))) int addr_encode(unsigned len, int testnet) {
    return len <= sizeof(spk) && address_encode(spk, len, testnet, out);
}
