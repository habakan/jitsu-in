#ifndef CORE_BIP32_H
#define CORE_BIP32_H

#include <stdint.h>
#include "secp256k1.h"

typedef struct {
    uint8_t key[32], chain[32];
} bip32_node_t;

int bip32_master(const uint8_t seed[64], bip32_node_t *out);
int bip32_derive(const secp256k1_context *ctx, const bip32_node_t *from, const uint32_t *path, unsigned depth,
                 bip32_node_t *out);
int bip32_pubkey(const secp256k1_context *ctx, const uint8_t key[32], uint8_t out[33]);
/* An unhardened child, given the parent's public key so that a loop over children computes it once */
int bip32_child(const bip32_node_t *parent, const uint8_t parent_pub[33], uint32_t i, bip32_node_t *out);

#endif
