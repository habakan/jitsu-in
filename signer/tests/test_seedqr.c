/* SeedQR decoding, against the published vectors */
#include <stdio.h>
#include <string.h>
#include "seedqr.h"
#include "seedqr_vectors.h"

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

int main(void) {
    char out[256];
    /* BIP39 all-zero entropy: abandon x11 + about, so the indices are 0,0,...,0,3 */
    const char *d12 = "000000000000000000000000000000000000000000000003";
    const uint8_t e12[16] = {0};
    /* the 24-word all-zero case: abandon x23 + art (indices 0 x23, 134) */
    const char *d24 = "000000000000000000000000000000000000000000000000"
                      "000000000000000000000000000000000000000000000102";
    const uint8_t e24[32] = {0};
    const char *want12 =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char *want24 =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    char bad[49];

    CHECK(seedqr_decode((const uint8_t *)d12, 48, out, sizeof(out)) > 0 && !strcmp(out, want12),
          "12 words from digits");
    CHECK(seedqr_decode((const uint8_t *)d24, 96, out, sizeof(out)) > 0 && !strcmp(out, want24),
          "24 words from digits");
    CHECK(seedqr_decode(e12, 16, out, sizeof(out)) > 0 && !strcmp(out, want12), "12 words from entropy");
    CHECK(seedqr_decode(e24, 32, out, sizeof(out)) > 0 && !strcmp(out, want24), "24 words from entropy");

    /* a bad checksum is refused */
    memcpy(bad, d12, 49);
    bad[47] = '4';
    CHECK(seedqr_decode((const uint8_t *)bad, 48, out, sizeof(out)) == 0, "bad checksum rejected");
    /* an index above 2047, a non-digit, a wrong length. 2048 has the same low 11 bits as 0, so the
     * checksum passes: without a range check this reads past the end of the word list */
    memcpy(bad, d12, 49);
    bad[0] = '2', bad[1] = '0', bad[2] = '4', bad[3] = '8';
    CHECK(seedqr_decode((const uint8_t *)bad, 48, out, sizeof(out)) == 0, "index 2048 rejected");
    memcpy(bad, d12, 49);
    bad[0] = '9', bad[1] = '9', bad[2] = '9', bad[3] = '9';
    CHECK(seedqr_decode((const uint8_t *)bad, 48, out, sizeof(out)) == 0, "index out of range rejected");
    memcpy(bad, d12, 49);
    bad[5] = 'x';
    CHECK(seedqr_decode((const uint8_t *)bad, 48, out, sizeof(out)) == 0, "non digit rejected");
    CHECK(seedqr_decode((const uint8_t *)d12, 47, out, sizeof(out)) == 0, "odd length rejected");
    CHECK(seedqr_decode((const uint8_t *)d12, 48, out, 50) == 0, "small buffer rejected");

    for (unsigned i = 0; i < sizeof(seedqr_vectors) / sizeof(seedqr_vectors[0]); i++) {
        const char *d = seedqr_vectors[i].digits, *m = seedqr_vectors[i].mnemonic;
        CHECK(seedqr_decode((const uint8_t *)d, strlen(d), out, sizeof(out)) > 0 && !strcmp(out, m),
              "published vector %u from digits", i + 1);
        CHECK(seedqr_decode(seedqr_vectors[i].compact, seedqr_vectors[i].len, out, sizeof(out)) > 0 && !strcmp(out, m),
              "published vector %u from compact", i + 1);
    }

    /* encoding: the words back into both forms, and those back into the words */
    for (unsigned i = 0; i < sizeof(seedqr_vectors) / sizeof(seedqr_vectors[0]); i++) {
        const char *m = seedqr_vectors[i].mnemonic, *d = seedqr_vectors[i].digits;
        uint8_t qr[96];
        int n = seedqr_encode((const uint8_t *)m, strlen(m), 0, qr, sizeof(qr));
        CHECK(n == (int)strlen(d) && !memcmp(qr, d, strlen(d)), "published vector %u to digits", i + 1);
        CHECK(seedqr_decode(qr, (size_t)n, out, sizeof(out)) > 0 && !strcmp(out, m), "vector %u digits round trip",
              i + 1);
        n = seedqr_encode((const uint8_t *)m, strlen(m), 1, qr, sizeof(qr));
        CHECK(n == (int)seedqr_vectors[i].len && !memcmp(qr, seedqr_vectors[i].compact, (size_t)n),
              "published vector %u to compact", i + 1);
        CHECK(seedqr_decode(qr, (size_t)n, out, sizeof(out)) > 0 && !strcmp(out, m), "vector %u compact round trip",
              i + 1);
    }
    {
        uint8_t qr[96];
        const char *bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                          "abandon";
        const char *w15 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                          "abandon abandon abandon address";
        CHECK(!seedqr_encode((const uint8_t *)bad, strlen(bad), 0, qr, sizeof(qr)), "bad checksum refused");
        CHECK(!seedqr_encode((const uint8_t *)w15, strlen(w15), 0, qr, sizeof(qr)), "15 words refused");
        CHECK(!seedqr_encode((const uint8_t *)want12, strlen(want12), 0, qr, 47), "a small buffer refused");
        CHECK(!seedqr_encode((const uint8_t *)want12, strlen(want12), 1, qr, 15), "a small compact buffer refused");
    }

    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
