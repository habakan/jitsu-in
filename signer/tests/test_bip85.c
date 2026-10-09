/* BIP85, against its own test vectors, which start from an xprv rather than a seed */
#include <stdio.h>
#include <string.h>
#include "bip85.h"
#include "core.h"
#include "sha512.h"
#include "secp256k1.h"

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
#define ROOT                                                                                                           \
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

static void hex(const uint8_t *p, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", p[i]);
}

/* base58 to the 82 bytes of a serialized xprv (78 and a checksum, not checked here) */
static void xprv_node(const char *s, bip32_node_t *node) {
    static const char *a = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    uint8_t b[82] = {0};
    for (; *s; s++) {
        unsigned carry = (unsigned)(strchr(a, *s) - a);
        for (int i = 81; i >= 0; i--) {
            carry += 58u * b[i];
            b[i] = (uint8_t)carry;
            carry >>= 8;
        }
    }
    memcpy(node->chain, b + 13, 32);
    memcpy(node->key, b + 46, 32);
}

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    bip32_node_t root;
    uint8_t ent[64];
    char h[129], mn[256];
    xprv_node(ROOT, &root);

    {
        const uint32_t p1[] = {83696968 | H, 0 | H, 0 | H}, p2[] = {83696968 | H, 0 | H, 1 | H};
        CHECK(bip85_entropy(ctx, &root, p1, 3, ent), "case 1");
        hex(ent, 64, h);
        CHECK(!strcmp(h,
                      "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a148"
                      "69e693da66ce94ac2da570ab7ee48618f7"),
              "case 1 entropy");
        CHECK(bip85_entropy(ctx, &root, p2, 3, ent), "case 2");
        hex(ent, 64, h);
        CHECK(!strcmp(h,
                      "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6d"
                      "f9095ab2b58d803b5b93ec9802085a690e"),
              "case 2 entropy");
    }
    CHECK(bip85_bip39(ctx, &root, 12, 0, mn, sizeof(mn)) > 0 &&
              !strcmp(mn, "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"),
          "12 words");
    CHECK(bip85_bip39(ctx, &root, 18, 0, mn, sizeof(mn)) > 0 &&
              !strcmp(mn,
                      "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital "
                      "hockey outdoor supply token"),
          "18 words");
    CHECK(bip85_bip39(ctx, &root, 24, 0, mn, sizeof(mn)) > 0 &&
              !strcmp(mn, "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce "
                          "twin tonight reason outdoor destroy simple truth cigar social volcano"),
          "24 words");
    CHECK(!bip85_bip39(ctx, &root, 15, 0, mn, sizeof(mn)), "15 words refused");
    CHECK(!bip85_bip39(ctx, &root, 12, H, mn, sizeof(mn)), "a hardened index refused");
    memset(mn, 0x55, sizeof(mn));
    CHECK(!bip85_bip39(ctx, &root, 24, 0, mn, 100), "a small buffer refused");
    {
        int clean = 1;
        for (unsigned k = 0; k < 100; k++) clean &= mn[k] == 0 || mn[k] == 0x55; /* cleared, or never written */
        CHECK(clean, "and none of the child's words are left in it");
    }
    CHECK(bip85_bip39(ctx, &root, 12, H - 1, mn, sizeof(mn)) > 0, "the largest index");

    /* through the core, which uses the loaded master */
    {
        static const char words[] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                                    "abandon abandon about";
        uint8_t seed[64];
        CHECK(core_init(CORE_MAINNET), "init");
        CHECK(!core_bip85_mnemonic(12, 0, mn, sizeof(mn)), "no seed");
        pbkdf2_hmac_sha512((const uint8_t *)words, sizeof(words) - 1, (const uint8_t *)"mnemonic", 8, 2048, seed);
        CHECK(core_load_seed(seed) && core_bip85_mnemonic(12, 0, mn, sizeof(mn)) > 0 &&
                  !strcmp(mn, "prosper short ramp prepare exchange stove life snack client enough purpose fold"),
              "from the loaded seed, the child the JavaScript suite derives independently");
        core_unload();
    }

    secp256k1_context_destroy(ctx);
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
