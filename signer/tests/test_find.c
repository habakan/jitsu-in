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

static int find(const char *addr, uint32_t chain, uint32_t count) {
    return core_find_address(addr, strlen(addr), 0, chain, count);
}

int main(void) {
    uint8_t seed[64];
    pbkdf2_hmac_sha512((const uint8_t *)MN, sizeof(MN) - 1, (const uint8_t *)"mnemonic", 8, 2048, seed);

    CHECK(core_init(CORE_MAINNET), "init");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 0, 10) == -CORE_ERR_NO_SEED, "no seed");
    CHECK(core_load_seed(seed), "load");

    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 0, 10) == 0, "BIP84 0/0");
    CHECK(find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 0, 10) == 1, "BIP84 0/1");
    CHECK(find("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", 1, 10) == 0, "BIP84 1/0");
    CHECK(find("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", 0, 10) == 0, "BIP86 0/0");
    CHECK(find("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh", 0, 10) == 1, "BIP86 0/1");
    CHECK(find("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", 1, 10) == 0, "BIP86 1/0");
    CHECK(find("BC1QNJG0JD8228AQ7EGYZACY8CYS3KNF9XVRERKF9G", 0, 10) == 1, "upper case, as a QR carries it");

    CHECK(find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 1, 10) == -CORE_ERR_NOT_FOUND, "receive is not change");
    CHECK(find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 0, 1) == -CORE_ERR_NOT_FOUND, "beyond count");
    CHECK(core_find_address("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 42, 1, 0, 10) == -CORE_ERR_NOT_FOUND,
          "another account");
    /* the BIP173 P2WSH example: ours in form, not in key */
    CHECK(find("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", 0, 10) == -CORE_ERR_NOT_FOUND,
          "P2WSH is not found");

    CHECK(find("BC1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 0, 10) == -CORE_ERR_FORMAT, "mixed case");
    CHECK(find("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", 0, 10) == -CORE_ERR_FORMAT, "testnet on mainnet");
    CHECK(find("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 0, 10) == -CORE_ERR_FORMAT, "base58");
    CHECK(find("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", 0, 10) == -CORE_ERR_FORMAT, "witness v2");
    CHECK(find("", 0, 10) == -CORE_ERR_FORMAT, "empty");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 2, 10) == -CORE_ERR_FORMAT, "chain 2");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 0, 0) == -CORE_ERR_FORMAT, "count 0");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 0, 100001) == -CORE_ERR_FORMAT, "count too large");
    CHECK(core_find_address("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 42, 0x80000000u, 0, 10) == -CORE_ERR_FORMAT,
          "hardened account");

    CHECK(core_init(CORE_TESTNET) && core_load_seed(seed), "load testnet");
    CHECK(find("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", 0, 10) == 0, "testnet BIP84 0/0");
    CHECK(find("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 0, 10) == -CORE_ERR_FORMAT, "mainnet on testnet");

    core_unload();
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
