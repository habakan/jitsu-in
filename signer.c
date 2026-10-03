#include <stdint.h>
#include <string.h>
#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "sha512.h"
#include "bip32.h"
#include "wipe.h"

#ifdef __wasm__
#define EXPORT(name) __attribute__((export_name(#name))) name
#else
#define EXPORT(name) name
#endif

static unsigned char ctx_mem[256] __attribute__((aligned(16)));
static secp256k1_context *ctx;
/* ホストとの受け渡し領域。seckey[32] msg[32] aux[32] out[64] */
static unsigned char io[160];

unsigned char *EXPORT(signer_io)(void) { return io; }

int EXPORT(signer_init)(void) {
    if (secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) > sizeof(ctx_mem)) return 0;
    ctx = secp256k1_context_preallocated_create(ctx_mem, SECP256K1_CONTEXT_NONE);
    return ctx != NULL;
}

int EXPORT(signer_sign_ecdsa)(void) {
    secp256k1_ecdsa_signature sig;
    int ok = secp256k1_ecdsa_sign(ctx, &sig, io + 32, io, NULL, NULL)
          && secp256k1_ecdsa_signature_serialize_compact(ctx, io + 96, &sig);
    memset(&sig, 0, sizeof(sig));
    return ok;
}

int EXPORT(signer_sign_schnorr)(void) {
    secp256k1_keypair kp;
    int ok = secp256k1_keypair_create(ctx, &kp, io)
          && secp256k1_schnorrsig_sign32(ctx, io + 96, io + 32, &kp, io + 64);
    memset(&kp, 0, sizeof(kp));
    return ok;
}

void EXPORT(signer_zeroize)(void) {
    volatile unsigned char *p = io;
    for (size_t i = 0; i < sizeof(io); i++) p[i] = 0;
}

/* 入力領域。seed_from_mnemonic では mnemonic || passphrase、bip32_derive では uint32 LE のパス */
static unsigned char in[512];
static unsigned char seed[64];

unsigned char *EXPORT(signer_in)(void) { return in; }

int EXPORT(signer_seed_from_mnemonic)(unsigned mn_len, unsigned pass_len) {
    unsigned char salt[8 + sizeof(in)];
    if (mn_len + pass_len > sizeof(in)) return 0;
    memcpy(salt, "mnemonic", 8);
    memcpy(salt + 8, in + mn_len, pass_len);
    pbkdf2_hmac_sha512(in, mn_len, salt, 8 + pass_len, 2048, seed);
    memset(salt, 0, sizeof(salt));
    memcpy(io + 96, seed, 64);
    return 1;
}

/* seed から in[] のパスで秘密鍵を導出し、圧縮公開鍵 33 byte を io+96 に書く */
int EXPORT(signer_bip32_derive)(unsigned depth) {
    uint32_t path[16];
    bip32_node_t master, node;
    int ok;
    if (depth > 16) return 0;
    memcpy(path, in, 4 * depth);
    ok = bip32_master(seed, &master) && bip32_derive(ctx, &master, path, depth, &node)
      && bip32_pubkey(ctx, node.key, io + 96);
    wipe(&master, sizeof(master));
    wipe(&node, sizeof(node));
    return ok;
}
