#ifndef CORE_ADDRESS_H
#define CORE_ADDRESS_H

#include <stddef.h>
#include <stdint.h>

/* scriptPubKey to a standard address string: base58check for P2PKH and P2SH, bech32 for witness v0,
 * bech32m for v1-v16 (BIP173 / BIP350). Returns 0 for anything non-standard, and the caller is
 * expected to show the raw script in hex instead */
#define ADDRESS_MAX 75 /* the longest case, a 40-byte v1-v16 program: hrp 2 + '1' + 65 + checksum 6 + NUL */

int address_encode(const uint8_t *spk, size_t len, int testnet, char out[ADDRESS_MAX]);

/* base58 with a four-byte checksum appended. Also how the 78-byte xpub is encoded */
#define BASE58CHECK_MAX_IN 78
#define BASE58CHECK_MAX_OUT 120
void base58check_data(const uint8_t *p, size_t n, char *out);

#endif
