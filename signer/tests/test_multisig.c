/* Registering a P2WSH sortedmulti wallet: the three formats it comes in, what makes one refused, and the
 * descriptor and addresses it gives back, against Bitcoin Core's getdescriptorinfo and deriveaddresses */
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

/* abandon x11 + about (ours), zoo x11 + wrong, legal winner ... yellow, each at m/48'/0'/0'/2' */
#define XPUB0                                                                                                          \
    "xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf"
#define XPUB1                                                                                                          \
    "xpub6FHZCoNb3tg3o1GAJQxSwgFNF8mLRtTk2GgkF7n5rwzoxBhUEdFWa8cyZRHqytAzKZWsKz8627cQEMCCfR5GDSv6yXegqirpgDUX41Pxybr"
#define XPUB2                                                                                                          \
    "xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX"
/* letter advice ... above, someone else's */
#define XPUB3                                                                                                          \
    "xpub6DnEBNkSJKBYQmsbhS1sP9cNdtU5c9PLFGCjTJmxicxc13WB8zNNGQazabQpyFAGW5bV9tMko4uBxDxjUKL6dSAcx1tEbgEHtgSqyRsekh6"
#define K0 "[73c5da0a/48h/0h/0h/2h]" XPUB0
#define K1 "[3f635a63/48h/0h/0h/2h]" XPUB1
#define K2 "[b8688df1/48h/0h/0h/2h]" XPUB2
#define K3 "[28645006/48h/0h/0h/2h]" XPUB3
#define DESC "wsh(sortedmulti(2," K0 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*))"
/* Core's getdescriptorinfo checksum, and its deriveaddresses for receive index 0 */
#define CHECKSUM "d9p6ar8k"
#define RECEIVE0 "bc1qea2gkgeszr7wm66x2ejkgdxm9nhg9462sszn75zmkhazev0t02vs70kkll"

static core_multisig_t ms;

static int load(const char *text) {
    return core_multisig_load(text, strlen(text), &ms);
}

int main(void) {
    uint8_t seed[64], cbor[1024];
    static const char mn[] =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    char canonical[CORE_MULTISIG_DESC_MAX];
    int n;

    pbkdf2_hmac_sha512((const uint8_t *)mn, sizeof(mn) - 1, (const uint8_t *)"mnemonic", 8, 2048, seed);
    CHECK(core_init(CORE_MAINNET) && core_load_seed(seed), "load mainnet");

    CHECK(core_multisig_cbor(cbor, sizeof(cbor)) == -CORE_ERR_WALLET, "no wallet, no crypto-output");
    CHECK(load(DESC) == CORE_OK, "a descriptor");
    CHECK(ms.threshold == 2 && ms.n == 3 && ms.ours == 0, "2 of 3, ours first");
    CHECK(ms.fingerprints[1] == 0x3f635a63 && ms.fingerprints[2] == 0xb8688df1, "the cosigners' fingerprints");
    CHECK(!strcmp(ms.receive, RECEIVE0), "the first receive address is Core's: %s", ms.receive);
    CHECK(!strcmp(ms.descriptor, DESC "#" CHECKSUM), "the descriptor with Core's checksum: %s", ms.descriptor);
    strcpy(canonical, ms.descriptor);
    CHECK(load(canonical) == CORE_OK && !strcmp(ms.descriptor, canonical), "its own descriptor reads back");
    canonical[strlen(canonical) - 1] ^= 1;
    CHECK(load(canonical) == CORE_ERR_FORMAT, "a wrong checksum");

    CHECK(load("wsh(sortedmulti(2," K1 "/**," K0 "/**," K2 "/**))") == CORE_OK && ms.ours == 1 &&
              !strcmp(ms.receive, RECEIVE0),
          "BSMS's /** and another key order give the same wallet");
    CHECK(load("wsh(sortedmulti(2,[73C5DA0A/48'/0'/0'/2']" XPUB0 "/0/*," K1 "/0/*," K2 "/0/*))") == CORE_OK &&
              !strcmp(ms.descriptor, DESC "#" CHECKSUM),
          "' and capitals in the origin, and /0/*");

    CHECK(load("BSMS 1.0\n" DESC "\n/0/*,/1/*\n" RECEIVE0 "\n") == CORE_OK, "BSMS");
    CHECK(load("BSMS 1.0\r\n" DESC
               "\r\nNo path restrictions\r\nBC1QEA2GKGESZR7WM66X2EJKGDXM9NHG9462SSZN75ZMKHAZEV0T02VS70KKLL") == CORE_OK,
          "BSMS with CRLF and an upper-case address");
    CHECK(load("BSMS 1.0\n" DESC "\n/0/*,/1/*\nbc1qc6p3lpt2e2wv0vukgyykx3ca8fhy6pvlfg7sgv8e3qej473jjmxs29860y") ==
              CORE_ERR_WALLET,
          "BSMS whose address is the first change address, not receive");
    CHECK(load("BSMS 1.1\n" DESC "\n/0/*,/1/*\n" RECEIVE0) == CORE_ERR_FORMAT, "another BSMS version");

    CHECK(load("# Coldcard Multisig setup file (created by Sparrow)\n#\nName: test\nPolicy: 2 of 3\n"
               "Derivation: m/48'/0'/0'/2'\nFormat: P2WSH\n\n73C5DA0A: " XPUB0 "\n3F635A63: " XPUB1 "\nB8688DF1: " XPUB2
               "\n") == CORE_OK &&
              !strcmp(ms.descriptor, DESC "#" CHECKSUM),
          "a Coldcard setup file");
    CHECK(load("Policy: 2 of 3\nDerivation: m/48'/0'/0'/2'\nFormat: P2SH\n73C5DA0A: " XPUB0 "\n3F635A63: " XPUB1
               "\nB8688DF1: " XPUB2) == CORE_ERR_FORMAT,
          "a setup file for P2SH");
    CHECK(load("Policy: 2 of 3\nDerivation: m/48'/0'/0'/2'\nFormat: P2WSH\n73C5DA0A: " XPUB0 "\n3F635A63: " XPUB1) ==
              CORE_ERR_FORMAT,
          "a setup file with fewer keys than its policy");
    CHECK(load("Policy: 2 of 3\nFormat: P2WSH\n73C5DA0A: " XPUB0 "\n3F635A63: " XPUB1 "\nB8688DF1: " XPUB2) ==
              CORE_ERR_FORMAT,
          "a setup file without a derivation");

    CHECK(load("wsh(sortedmulti(2," K3 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*))") == CORE_ERR_WALLET,
          "a wallet without our key");
    CHECK(load("wsh(sortedmulti(2,[73c5da0a/48h/0h/0h/2h]" XPUB3 "/<0;1>/*," K1 "/<0;1>/*))") == CORE_ERR_WALLET,
          "our fingerprint on someone else's key, as with the wrong passphrase");
    CHECK(load("wsh(sortedmulti(2,[73c5da0a/48h/0h/1h/2h]" XPUB0 "/<0;1>/*," K1 "/<0;1>/*))") == CORE_ERR_WALLET,
          "our key at an origin it was not derived at");
    CHECK(load("wsh(sortedmulti(2," K0 "/<0;1>/*," K0 "/<0;1>/*))") == CORE_ERR_FORMAT, "a key twice");
    CHECK(load("wsh(sortedmulti(4," K0 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*))") == CORE_ERR_FORMAT,
          "a threshold above the keys");
    CHECK(load("wsh(sortedmulti(1," K0 "/<0;1>/*," K1 "/<0;1>/*," K2 "/<0;1>/*," K3 "/<0;1>/*))") == CORE_ERR_FORMAT,
          "four keys");
    CHECK(load("wsh(multi(2," K0 "/<0;1>/*," K1 "/<0;1>/*))") == CORE_ERR_FORMAT, "multi() rather than sortedmulti()");
    CHECK(load("sh(wsh(sortedmulti(2," K0 "/<0;1>/*," K1 "/<0;1>/*)))") == CORE_ERR_FORMAT, "P2SH-P2WSH");
    CHECK(load("wsh(sortedmulti(2," K0 "/<0;1>/*," K1 "/2/*))") == CORE_ERR_FORMAT, "a child other than 0 or 1");
    CHECK(load("wsh(sortedmulti(2,[73c5da0a/48h/0h/0h/2]" XPUB0 "/<0;1>/*," K1 "/<0;1>/*))") == CORE_ERR_FORMAT,
          "an unhardened origin step");
    CHECK(load("wsh(sortedmulti(2,[73c5da0a/48h/0h/0h]" XPUB0 "/<0;1>/*," K1 "/<0;1>/*))") == CORE_ERR_FORMAT,
          "an origin shallower than the xpub");
    {
        char bad[] = DESC;
        bad[strstr(bad, "xpub6DkF") - bad + 20] ^= 1;
        CHECK(load(bad) == CORE_ERR_FORMAT, "an xpub with a broken base58 checksum");
    }

    CHECK(load(DESC) == CORE_OK, "loaded again");
    n = core_multisig_cbor(cbor, sizeof(cbor));
    CHECK(n > 0 && cbor[0] == 0xd9 && cbor[1] == 0x01 && cbor[2] == 0x91 && cbor[3] == 0xd9 && cbor[4] == 0x01 &&
              cbor[5] == 0x97,
          "crypto-output starts wsh (401), sortedmulti (407)");
    n = core_account_cbor(0, cbor, sizeof(cbor));
    CHECK(n > 0 && cbor[0] == 0xa2 && cbor[1] == 0x01 && cbor[2] == 0x1a && cbor[3] == 0x73 && cbor[7] == 0x02 &&
              cbor[8] == 0x84,
          "crypto-account: our fingerprint and four outputs");
    CHECK(core_account_cbor(0, cbor, 100) == -CORE_ERR_FORMAT, "a buffer too small");

    core_unload();
    CHECK(core_multisig_cbor(cbor, sizeof(cbor)) == -CORE_ERR_WALLET, "unloading the seed unloads the wallet");
    CHECK(load(DESC) == CORE_ERR_NO_SEED, "no seed, no wallet");

    CHECK(core_init(CORE_TESTNET) && core_load_seed(seed), "load testnet");
    CHECK(load(DESC) == CORE_ERR_FORMAT, "a mainnet xpub on testnet");

    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
