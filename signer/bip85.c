#include "bip85.h"
#include "seedqr.h"
#include "sha512.h"
#include "wipe.h"

#define H 0x80000000u

int bip85_entropy(const secp256k1_context *ctx, const bip32_node_t *root, const uint32_t *path, unsigned depth,
                  uint8_t out[64]) {
    bip32_node_t node;
    hmac_sha512_ctx h;
    int ok = 1;
    for (unsigned i = 0; i < depth; i++) ok &= (path[i] & H) != 0;
    ok = ok && bip32_derive(ctx, root, path, depth, &node);
    if (ok) {
        hmac_sha512_init(&h, (const unsigned char *)"bip-entropy-from-k", 18);
        sha512_update(&h.inner, node.key, 32);
        hmac_sha512_final(&h, out);
    }
    wipe(&node, sizeof(node));
    wipe(&h, sizeof(h));
    return ok;
}

int bip85_bip39(const secp256k1_context *ctx, const bip32_node_t *root, unsigned words, uint32_t index, char *out,
                size_t cap) {
    const uint32_t path[5] = {83696968u | H, 39u | H, 0u | H, words | H, index | H};
    uint8_t ent[64];
    int n = 0;
    if ((words == 12 || words == 18 || words == 24) && index < H && bip85_entropy(ctx, root, path, 5, ent))
        n = bip39_mnemonic_from_entropy(ent, words * 4 / 3, out, cap);
    wipe(ent, sizeof(ent));
    return n;
}
