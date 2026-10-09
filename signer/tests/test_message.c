/* BIP137 message signing: the header byte, the key it recovers to, and the review it is bound to */
#include <stdio.h>
#include <string.h>
#include "bip32.h"
#include "core.h"
#include "sha256.h"
#include "sha512.h"
#include "secp256k1.h"
#include "secp256k1_recovery.h"

static int checks, failures;
#define CHECK(cond, ...)                                                                                               \
    do {                                                                                                               \
        checks++;                                                                                                      \
        if (!(cond)) {                                                                                                 \
            failures++;                                                                                                \
            printf("FAIL ");                                                                                           \
            printf(__VA_ARGS__);                                                                                       \
            printf("\n");                                                                                              \
        }                                                                                                              \
    } while (0)

#define H 0x80000000u
#define MSG "This is an example of a signed message."

static uint8_t seed[64];

/* The key the signature has to recover to, derived here rather than asked of the core */
static int recovers_to(const secp256k1_context *ctx, const uint8_t sig[65], const char *msg, size_t len,
                       const uint32_t path[5]) {
    static const char prefix[] = "\x18"
                                 "Bitcoin Signed Message:\n";
    uint8_t buf[600], hash[32], want[33], got[33];
    size_t n = 0, out = 33;
    bip32_node_t m, node;
    secp256k1_ecdsa_recoverable_signature rs;
    secp256k1_pubkey pub;

    memcpy(buf, prefix, 25), n = 25;
    buf[n++] = (uint8_t)len; /* every message here is below 0xfd */
    memcpy(buf + n, msg, len), n += len;
    sha256(buf, n, hash);
    sha256(hash, 32, hash);
    if (!bip32_master(seed, &m) || !bip32_derive(ctx, &m, path, 5, &node) || !bip32_pubkey(ctx, node.key, want))
        return 0;
    return secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rs, sig + 1, (sig[0] - 27) & 3) &&
           secp256k1_ecdsa_recover(ctx, &pub, &rs, hash) &&
           secp256k1_ec_pubkey_serialize(ctx, got, &out, &pub, SECP256K1_EC_COMPRESSED) && !memcmp(got, want, 33);
}

static int review(const char *msg, size_t len, unsigned purpose, uint32_t chain, uint32_t index, core_message_t *m) {
    return core_message_review((const uint8_t *)msg, len, purpose, 0, chain, index, m);
}

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    static const char words[] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                                "abandon about";
    const uint32_t p84[5] = {84 | H, H, H, 0, 0}, p49[5] = {49 | H, H, H, 1, 7};
    core_message_t m;
    uint8_t sig[65];
    char big[513];

    pbkdf2_hmac_sha512((const uint8_t *)words, sizeof(words) - 1, (const uint8_t *)"mnemonic", 8, 2048, seed);
    CHECK(core_init(CORE_MAINNET), "init");
    CHECK(review(MSG, strlen(MSG), 84, 0, 0, &m) == CORE_ERR_NO_SEED, "no seed");
    CHECK(core_load_seed(seed), "load");

    CHECK(review(MSG, strlen(MSG), 84, 0, 0, &m) == CORE_OK, "review P2WPKH");
    CHECK(!strcmp(m.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"), "BIP84's first address is shown");
    CHECK(m.text_kind == CORE_TEXT_MESSAGE && !strcmp(m.text, MSG), "printable text is shown as it is");
    CHECK(core_message_sign(sig) == CORE_OK, "sign");
    CHECK(sig[0] >= 39 && sig[0] <= 42, "BIP137's P2WPKH header, %d", sig[0]);
    CHECK(recovers_to(ctx, sig, MSG, strlen(MSG), p84), "recovers to m/84'/0'/0'/0/0");
    CHECK(core_message_sign(sig) == CORE_ERR_NOT_REVIEWED, "one review permits one signature");

    CHECK(review("", 0, 49, 1, 7, &m) == CORE_OK && m.address[0] == '3', "review P2SH-P2WPKH, change 7");
    CHECK(m.text_kind == CORE_TEXT_MESSAGE && !m.text[0], "an empty message");
    CHECK(core_message_sign(sig) == CORE_OK && sig[0] >= 35 && sig[0] <= 38, "BIP137's P2SH-P2WPKH header");
    CHECK(recovers_to(ctx, sig, "", 0, p49), "recovers to m/49'/0'/0'/1/7");

    CHECK(review("line\nbreak", 10, 84, 0, 0, &m) == CORE_OK && m.text_kind == CORE_TEXT_HEX &&
              !strcmp(m.text, "6c696e650a627265616b"),
          "anything but printable ASCII is shown in hex");
    CHECK(review("caf\xc3\xa9", 5, 84, 0, 0, &m) == CORE_OK && m.text_kind == CORE_TEXT_HEX, "UTF-8 too");

    memset(big, 'a', sizeof(big));
    CHECK(review(big, 512, 84, 0, 0, &m) == CORE_OK, "512 bytes");
    CHECK(review(big, 513, 84, 0, 0, &m) == CORE_ERR_FORMAT, "513 bytes refused");
    CHECK(core_message_sign(sig) == CORE_ERR_NOT_REVIEWED, "a refused review leaves nothing to sign");
    CHECK(review(MSG, strlen(MSG), 86, 0, 0, &m) == CORE_ERR_FORMAT, "P2TR is not BIP137");
    CHECK(review(MSG, strlen(MSG), 44, 0, 0, &m) == CORE_ERR_FORMAT, "BIP44 refused");
    CHECK(review(MSG, strlen(MSG), 84, 2, 0, &m) == CORE_ERR_FORMAT, "chain 2 refused");
    CHECK(review(MSG, strlen(MSG), 84, 0, 100000, &m) == CORE_ERR_FORMAT, "index 100000 refused");
    CHECK(core_message_review((const uint8_t *)MSG, strlen(MSG), 84, H, 0, 0, &m) == CORE_ERR_FORMAT,
          "a hardened account refused");

    core_unload();
    CHECK(core_message_sign(sig) == CORE_ERR_NOT_REVIEWED, "unload forgets the review");
    secp256k1_context_destroy(ctx);
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
