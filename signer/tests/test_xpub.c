/* The xpub and the output descriptor, against BIP32's vectors */
#include <stdio.h>
#include <string.h>
#include "core.h"
#include "sha512.h"

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

#define MN "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

#define H 0x80000000u

/* base58 to its 82 bytes (78 and the checksum), without checking anything */
static void b58(const char *s, uint8_t b[82]) {
    static const char *a = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    memset(b, 0, 82);
    for (; *s; s++) {
        unsigned carry = (unsigned)(strchr(a, *s) - a);
        for (int i = 81; i >= 0; i--) {
            carry += 58u * b[i];
            b[i] = (uint8_t)carry;
            carry >>= 8;
        }
    }
}

int main(void) {
    uint8_t seed[64];
    char xpub[CORE_XPUB_MAX], desc[CORE_DESC_MAX];

    pbkdf2_hmac_sha512((const uint8_t *)MN, sizeof(MN) - 1, (const uint8_t *)"mnemonic", 8, 2048, seed);

    CHECK(core_init(CORE_MAINNET) && core_load_seed(seed), "load mainnet");
    CHECK(core_account_xpub(84, 0, xpub, desc) == CORE_OK, "mainnet BIP84 xpub");
    printf("  %s\n", desc);
    /* BIP84's own test vector (m/84'/0'/0') */
    CHECK(!strcmp(xpub, "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXY"
                        "VUhLv1VMrjPC7PW6V"),
          "BIP84 test vector");
    CHECK(!strncmp(desc, "wpkh([73c5da0a/84h/0h/0h]xpub6CatW", 34), "BIP84 descriptor");

    /* BIP86's own test vector (m/86'/0'/0') */
    CHECK(core_account_xpub(86, 0, xpub, desc) == CORE_OK, "mainnet BIP86 xpub");
    printf("  %s\n", desc);
    CHECK(!strcmp(xpub, "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfd"
                        "DEHGCtMMj92pReUsQ"),
          "BIP86 test vector");
    CHECK(!strncmp(desc, "tr([73c5da0a/86h/0h/0h]xpub6BgBg", 32) && strstr(desc, "/<0;1>/*)"), "BIP86 descriptor");

    CHECK(core_account_xpub(49, 0, xpub, desc) == CORE_OK, "mainnet BIP49 xpub");
    printf("  %s\n", desc);
    CHECK(!strncmp(desc, "sh(wpkh([73c5da0a/49h/0h/0h]xpub", 32) && strstr(desc, "/<0;1>/*))"), "BIP49 descriptor");

    /* BIP48 P2WSH (m/48'/0'/0'/2'), the key expression a sortedmulti() takes; embit derives the same xpub */
    CHECK(core_account_xpub(48, 0, xpub, desc) == CORE_OK, "mainnet BIP48 xpub");
    printf("  %s\n", desc);
    CHECK(!strcmp(xpub,
                  "xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR2"
                  "8mCyxUFL4r6KFrf"),
          "BIP48 xpub");
    CHECK(!strncmp(desc, "[73c5da0a/48h/0h/0h/2h]xpub6DkFA", 32) && strstr(desc, "KFrf/<0;1>/*") &&
              desc[strlen(desc) - 1] == '*',
          "BIP48 key expression");
    CHECK(core_account_xpub(48, 3, xpub, desc) == CORE_OK && strstr(desc, "/48h/0h/3h/2h]"), "BIP48 account 3");

    CHECK(core_account_xpub(86, H - 1, xpub, desc) == CORE_OK && strstr(desc, "/86h/0h/2147483647h]"),
          "the largest account");
    CHECK(core_account_xpub(84, 1, xpub, desc) == CORE_OK && strstr(desc, "/84h/0h/1h]"), "account 1");
    CHECK(core_account_xpub(84, H, xpub, desc) == CORE_ERR_FORMAT, "a hardened account refused");
    CHECK(core_account_xpub(0, 0, xpub, desc) == CORE_ERR_FORMAT, "purpose 0 refused");

    CHECK(core_init(CORE_TESTNET) && core_load_seed(seed), "load testnet");
    CHECK(core_account_xpub(84, 0, xpub, desc) == CORE_OK, "testnet BIP84 xpub");
    printf("  %s\n", desc);
    CHECK(!strncmp(xpub, "tpub", 4) && strstr(desc, "wpkh([73c5da0a/84h/1h/0h]") && strstr(desc, "/<0;1>/*)"),
          "testnet BIP84 shape");
    /* BIP49's own vector is testnet, m/49'/1'/0', written with SLIP-132's upub version: the same 74 bytes
     * after the version as the tpub here */
    CHECK(core_account_xpub(49, 0, xpub, desc) == CORE_OK, "testnet BIP49 xpub");
    {
        uint8_t ours[82], want[82];
        b58(xpub, ours);
        b58("upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknF"
            "HYfgY",
            want);
        CHECK(!memcmp(ours + 4, want + 4, 74), "BIP49 test vector, after the version");
    }
    CHECK(core_account_xpub(86, 0, xpub, desc) == CORE_OK, "testnet BIP86 xpub");
    CHECK(!strncmp(xpub, "tpub", 4) && strstr(desc, "tr([73c5da0a/86h/1h/0h]"), "testnet BIP86 shape");
    CHECK(core_account_xpub(48, 0, xpub, desc) == CORE_OK && !strncmp(xpub, "tpub", 4) &&
              !strncmp(desc, "[73c5da0a/48h/1h/0h/2h]tpub", 27),
          "testnet BIP48 shape");

    core_unload();
    CHECK(core_account_xpub(84, 0, xpub, desc) == CORE_ERR_NO_SEED, "no seed -> no xpub");
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
