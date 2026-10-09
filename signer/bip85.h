#ifndef CORE_BIP85_H
#define CORE_BIP85_H
/* BIP85: child entropy, and child BIP39 mnemonics, deterministically from a root key */
#include <stddef.h>
#include <stdint.h>
#include "bip32.h"

/* HMAC-SHA512 keyed "bip-entropy-from-k" over the private key at path (every step hardened) */
int bip85_entropy(const secp256k1_context *ctx, const bip32_node_t *root, const uint32_t *path, unsigned depth,
                  uint8_t out[64]);

/* The English mnemonic at m/83696968'/39'/0'/words'/index': words is 12, 18 or 24 and index below 2^31.
 * Returns its length, NUL-terminated in out, or 0 */
int bip85_bip39(const secp256k1_context *ctx, const bip32_node_t *root, unsigned words, uint32_t index, char *out,
                size_t cap);

#endif
