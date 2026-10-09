/* Finding which of our addresses an address is, against BIP84's and BIP86's vectors */
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

/* receive (chain 0) is searched first, then change; the result is chain << 20 | index */
static int find(const char *addr, uint32_t count) {
    return core_find_address(addr, strlen(addr), 0, count);
}

int main(void) {
    uint8_t seed[64];
    pbkdf2_hmac_sha512((const uint8_t *)MN, sizeof(MN) - 1, (const uint8_t *)"mnemonic", 8, 2048, seed);

    CHECK(core_init(CORE_MAINNET), "init");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 10) == -CORE_ERR_NO_SEED, "no seed");
    CHECK(core_load_seed(seed), "load");

    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 10) == 0, "BIP84 0/0");
    CHECK(find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 10) == 1, "BIP84 0/1");
    CHECK(find("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", 10) == (1 << 20), "BIP84 1/0");
    CHECK(find("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", 10) == 0, "BIP86 0/0");
    CHECK(find("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh", 10) == 1, "BIP86 0/1");
    CHECK(find("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", 10) == (1 << 20), "BIP86 1/0");
    CHECK(find("BC1QNJG0JD8228AQ7EGYZACY8CYS3KNF9XVRERKF9G", 10) == 1, "upper case, as a QR carries it");
    /* BIP49, in base58, whose case is part of the address: the change in own_mixed_p2sh_nwu, m/49'/0'/0'/1/0 */
    CHECK(find("34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7", 10) == (1 << 20), "BIP49 1/0");
    CHECK(find("34K56KSjgUCUSD8GTtuF7c9Zzwokbs6uZ7", 10) == -CORE_ERR_NOT_FOUND,
          "base58 with one letter's case changed is not ours");
    CHECK(find("34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ0", 10) == -CORE_ERR_FORMAT, "0 is not base58");

    CHECK(find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 1) == -CORE_ERR_NOT_FOUND, "beyond count");
    CHECK(core_find_address("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 42, 1, 10) == -CORE_ERR_NOT_FOUND,
          "another account");
    /* the BIP173 P2WSH example: ours in form, not in key */
    CHECK(find("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", 10) == -CORE_ERR_NOT_FOUND,
          "P2WSH is not found");

    CHECK(find("BC1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 10) == -CORE_ERR_FORMAT, "mixed case");
    CHECK(find("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", 10) == -CORE_ERR_FORMAT, "testnet on mainnet");
    CHECK(find("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 10) == -CORE_ERR_FORMAT, "base58");
    CHECK(find("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", 10) == -CORE_ERR_FORMAT, "witness v2");
    CHECK(find("", 10) == -CORE_ERR_FORMAT, "empty");
    /* a NUL ends the address strcmp would see, and whatever follows it must not pass unread */
    CHECK(core_find_address("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g\0junk", 47, 0, 10) == -CORE_ERR_FORMAT,
          "a NUL inside refused");
    CHECK(find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g!", 10) == -CORE_ERR_FORMAT, "a character bech32 lacks");
    CHECK(find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9", 100000) == -CORE_ERR_NOT_FOUND,
          "a truncated address is not found, without searching");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 0) == -CORE_ERR_FORMAT, "count 0");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 100001) == -CORE_ERR_FORMAT, "count too large");
    CHECK(core_find_address("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 42, 0x80000000u, 10) == -CORE_ERR_FORMAT,
          "hardened account");

    CHECK(core_init(CORE_TESTNET) && core_load_seed(seed), "load testnet");
    CHECK(find("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", 10) == 0, "testnet BIP84 0/0");
    CHECK(find("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", 10) == 0, "BIP49's own testnet vector, m/49'/1'/0'/0/0");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 10) == -CORE_ERR_FORMAT, "mainnet on testnet");

    core_unload();
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
