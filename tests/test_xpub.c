/* xpub と出力ディスクリプタを BIP32 のベクタと突き合わせる */
#include <stdio.h>
#include <string.h>
#include "core.h"
#include "sha512.h"

static int checks, failures;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } } while (0)

#define MN "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

int main(void) {
    uint8_t seed[64];
    char xpub[CORE_XPUB_MAX], desc[CORE_DESC_MAX];

    pbkdf2_hmac_sha512((const uint8_t *)MN, sizeof(MN) - 1, (const uint8_t *)"mnemonic", 8, 2048, seed);

    CHECK(core_init(CORE_MAINNET) && core_load_seed(seed), "load mainnet");
    CHECK(core_account_xpub(xpub, desc), "mainnet xpub");
    printf("  mainnet %s\n  %s\n", xpub, desc);
    /* BIP84 の公式テストベクタ（m/84'/0'/0'） */
    CHECK(!strcmp(xpub, "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"), "BIP84 test vector");

    CHECK(core_init(CORE_TESTNET) && core_load_seed(seed), "load testnet");
    CHECK(core_account_xpub(xpub, desc), "testnet xpub");
    printf("  testnet %s\n  %s\n", xpub, desc);
    CHECK(!strncmp(xpub, "tpub", 4), "testnet prefix");
    CHECK(strstr(desc, "/84h/1h/0h]") && strstr(desc, "/<0;1>/*)"), "descriptor shape");

    core_unload();
    CHECK(!core_account_xpub(xpub, desc), "no seed -> no xpub");
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
