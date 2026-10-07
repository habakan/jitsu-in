/* Checking a typed mnemonic, against BIP39's reference vectors */
#include <stdio.h>
#include <string.h>
#include "seedqr.h"
#include "sha512.h"
#include "bip39_vectors.h"

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

static int ok(const char *mn) {
    return bip39_mnemonic_ok((const uint8_t *)mn, strlen(mn));
}

int main(void) {
    for (unsigned i = 0; i < sizeof(bip39_vectors) / sizeof(bip39_vectors[0]); i++) {
        const char *mn = bip39_vectors[i].mnemonic;
        uint8_t seed[64];
        char hex[129];
        CHECK(ok(mn), "vector %u accepted", i);
        pbkdf2_hmac_sha512((const uint8_t *)mn, strlen(mn), (const uint8_t *)"mnemonicTREZOR", 14, 2048, seed);
        for (unsigned k = 0; k < 64; k++) snprintf(hex + 2 * k, 3, "%02x", seed[k]);
        CHECK(!strcmp(hex, bip39_vectors[i].seed), "vector %u seed", i);
    }

    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"),
          "bad checksum refused");
    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abaut"),
          "a word not in the list refused");
    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
          "11 words refused");
    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
              "about"),
          "13 words refused");
    CHECK(!ok(" abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
          "a leading space refused");
    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about "),
          "a trailing space refused");
    CHECK(!ok("abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
          "two spaces refused");
    CHECK(!ok("Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
          "capitals refused");
    CHECK(!ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandonx"),
          "a word longer than any in the list refused");
    {
        static const char nul[] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                                  "abandon about\0";
        CHECK(!bip39_mnemonic_ok((const uint8_t *)nul, sizeof(nul) - 1), "a word padded with NUL refused");
    }
    CHECK(!bip39_mnemonic_ok((const uint8_t *)"about", 0), "empty refused");
    CHECK(!ok("\xe3\x81\x82\xe3\x81\x84\xe3\x81\x93\xe3\x81\x8f\xe3\x81\x97\xe3\x82\x93"),
          "a non-English word refused");

    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
