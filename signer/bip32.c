#include "bip32.h"
#include <string.h>
#include "wipe.h"
#include "sha512.h"

int bip32_pubkey(const secp256k1_context *ctx, const uint8_t key[32], uint8_t out[33]) {
    secp256k1_pubkey pub;
    size_t len = 33;
    return secp256k1_ec_pubkey_create(ctx, &pub, key)
        && secp256k1_ec_pubkey_serialize(ctx, out, &len, &pub, SECP256K1_EC_COMPRESSED);
}

int bip32_master(const uint8_t seed[64], bip32_node_t *out) {
    hmac_sha512_ctx h;
    uint8_t I[64];
    hmac_sha512_init(&h, (const uint8_t *)"Bitcoin seed", 12);
    sha512_update(&h.inner, seed, 64);
    hmac_sha512_final(&h, I);
    memcpy(out->key, I, 32);
    memcpy(out->chain, I + 32, 32);
    wipe(I, sizeof(I));
    wipe(&h, sizeof(h));
    return secp256k1_ec_seckey_verify(secp256k1_context_static, out->key);
}

int bip32_derive(const secp256k1_context *ctx, const bip32_node_t *from, const uint32_t *path, unsigned depth,
                 bip32_node_t *out) {
    uint8_t data[37], I[64];
    hmac_sha512_ctx h;
    int ok = 1;

    *out = *from;
    for (unsigned d = 0; ok && d < depth; d++) {
        if (path[d] & 0x80000000u) {
            data[0] = 0;
            memcpy(data + 1, out->key, 32);
        } else {
            ok = bip32_pubkey(ctx, out->key, data);
        }
        for (int i = 0; i < 4; i++) data[33 + i] = (uint8_t)(path[d] >> (24 - 8 * i));
        hmac_sha512_init(&h, out->chain, 32);
        sha512_update(&h.inner, data, 37);
        hmac_sha512_final(&h, I);
        ok = ok && secp256k1_ec_seckey_tweak_add(ctx, out->key, I);
        memcpy(out->chain, I + 32, 32);
    }
    wipe(data, sizeof(data));
    wipe(I, sizeof(I));
    wipe(&h, sizeof(h));
    if (!ok) wipe(out, sizeof(*out));
    return ok;
}
