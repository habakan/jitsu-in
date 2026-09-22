/* Checks the UR building blocks and the decoder against the bc-ur reference test suite. */
#include <stdio.h>
#include <string.h>
#include "ur.h"
#include "ur_ref_vectors.h"

static int checks, failures;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; printf("FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void seed_str(ur_rng_t *r, const char *s) { ur_rng_seed(r, (const uint8_t *)s, strlen(s)); }

/* make_message() of the reference tests: bytes from Xoshiro256 seeded with a string */
static void make_message(uint8_t *out, size_t n, const char *seed) {
    ur_rng_t r;
    seed_str(&r, seed);
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)ur_rng_next_int(&r, 0, 255);
}

/* The UR "bytes" message: a CBOR byte string holding make_message(n, "Wolf") */
static size_t make_message_cbor(uint8_t *out, size_t n) {
    size_t h = n < 24 ? 1 : n < 256 ? 2 : 3;
    out[0] = (uint8_t)(0x40 | (n < 24 ? n : n < 256 ? 24 : 25));
    if (h == 2) out[1] = (uint8_t)n;
    if (h == 3) out[1] = (uint8_t)(n >> 8), out[2] = (uint8_t)n;
    make_message(out + h, n, "Wolf");
    return h + n;
}

static long feed(const char *part) {
    static char buf[1024];
    size_t n = strlen(part);
    memcpy(buf, part, n);
    return ur_decoder_receive(buf, n);
}

int main(void) {
    static uint8_t work[4096], out[4096], expect[4096];
    ur_rng_t r;

    CHECK(ur_crc32((const uint8_t *)"Hello, world!", 13) == 0xebe6c6e6, "crc32 hello");
    CHECK(ur_crc32((const uint8_t *)"Wolf", 4) == 0x598c84dc, "crc32 wolf");

    {
        static const uint8_t want[5] = {0, 1, 2, 128, 255};
        char s[64] = "aeadaolazmjendeoti";
        CHECK(ur_bytewords_decode(s, strlen(s), out, sizeof(out)) == 5 && !memcmp(out, want, 5), "bytewords 1");
        strcpy(s, "aeadaolazojendeowf");
        CHECK(ur_bytewords_decode(s, strlen(s), out, sizeof(out)) < 0, "bytewords bad checksum");
        CHECK(ur_bytewords_decode(REF_BYTEWORDS_2_MINIMAL, strlen(REF_BYTEWORDS_2_MINIMAL), out, sizeof(out)) == 100
              && !memcmp(out, REF_BYTEWORDS_2_INPUT, 100), "bytewords 2");
    }

    seed_str(&r, "Wolf");
    for (int i = 0; i < 100; i++) CHECK(ur_rng_next(&r) % 100 == REF_RNG_1[i], "rng 1 [%d]", i);
    {
        uint32_t c = ur_crc32((const uint8_t *)"Wolf", 4);
        uint8_t be[4] = {(uint8_t)(c >> 24), (uint8_t)(c >> 16), (uint8_t)(c >> 8), (uint8_t)c};
        ur_rng_seed(&r, be, 4);
        for (int i = 0; i < 100; i++) CHECK(ur_rng_next(&r) % 100 == REF_RNG_2[i], "rng 2 [%d]", i);
    }
    seed_str(&r, "Wolf");
    for (int i = 0; i < 100; i++) CHECK(ur_rng_next_int(&r, 1, 10) == REF_RNG_3[i], "rng 3 [%d]", i);

    {
        static const double w[4] = {1, 2, 4, 8};
        double probs[4];
        int aliases[4];
        ur_sampler_init(w, 4, probs, aliases);
        seed_str(&r, "Wolf");
        for (int i = 0; i < 500; i++) CHECK(ur_sampler_next(probs, aliases, 4, &r) == REF_SAMPLER[i], "sampler [%d]", i);
    }

    seed_str(&r, "Wolf");
    for (int k = 0; k < 10; k++) {
        uint16_t v[10];
        for (int i = 0; i < 10; i++) v[i] = (uint16_t)(i + 1);
        ur_shuffle(v, 10, &r);
        for (int i = 0; i < 10; i++) CHECK(v[i] == REF_SHUFFLE[10 * k + i], "shuffle %d [%d]", k, i);
    }

    /* make_message(1024) splits into 11 fragments with the reference encoder's nominal length */
    for (int nonce = 1; nonce <= 200; nonce++) {
        char seed[16];
        snprintf(seed, sizeof(seed), "Wolf-%d", nonce);
        seed_str(&r, seed);
        CHECK(ur_choose_degree(11, &r) == REF_DEGREES[nonce - 1], "degree nonce %d", nonce);
    }
    {
        uint8_t msg[1024], bits[UR_MAX_SEQ_LEN / 8];
        const int *ref = REF_FRAGMENTS;
        make_message(msg, sizeof(msg), "Wolf");
        uint32_t checksum = ur_crc32(msg, sizeof(msg));
        for (uint32_t seq = 1; seq <= 30; seq++) {
            int count = *ref++, ok = 1;
            size_t got = ur_choose_fragments(seq, 11, checksum, bits);
            for (int i = 0, k = 0; i < 11; i++) {
                if (!(bits[i / 8] >> (i % 8) & 1)) continue;
                ok &= k < count && ref[k++] == i;
            }
            CHECK(ok && got == (size_t)count, "fragments seq %u", seq);
            ref += count;
        }
    }

    /* single-part UR of make_message(50) */
    ur_decoder_reset(work, sizeof(work));
    {
        size_t n = make_message_cbor(expect, 50);
        CHECK(feed(REF_SINGLE_PART) == (long)n && !memcmp(ur_decoder_message(), expect, n)
              && !strcmp(ur_decoder_type(), "bytes"), "single part");
    }

    /* multipart UR of make_message(256): the 9 pure parts, then only the mixed parts 10..20 */
    {
        size_t n = make_message_cbor(expect, 256);
        long rc = 0;
        unsigned expected, received;
        ur_decoder_reset(work, sizeof(work));
        for (int i = 0; i < 9 && rc == 0; i++) rc = feed(REF_PARTS[i]);
        CHECK(rc == (long)n && !memcmp(ur_decoder_message(), expect, n), "multipart pure parts");

        /* parts 10..20 alone do not determine the message (the reference decoder does not complete either);
         * a pure part then finishes it */
        ur_decoder_reset(work, sizeof(work));
        rc = 0;
        for (int i = 9; i < 20 && rc == 0; i++) rc = feed(REF_PARTS[i]);
        ur_decoder_progress(&expected, &received);
        CHECK(rc == 0 && expected == 9 && received == 8, "mixed parts only stop at 8/9 (rc=%ld, %u/%u)", rc, received,
              expected);
        for (int i = 0; i < 9 && rc == 0; i++) rc = feed(REF_PARTS[i]);
        CHECK(rc == (long)n && !memcmp(ur_decoder_message(), expect, n), "mixed parts then pure parts");

        /* uppercase (QR alphanumeric mode), a dropped pure part, and parts arriving out of order. The reference
         * decoder (@ngraveio/bc-ur) completes this sequence after 16 parts too */
        ur_decoder_reset(work, sizeof(work));
        rc = 0;
        int used = 0;
        for (int i = 19; i >= 0 && rc == 0; i--) {
            char up[256];
            size_t k = 0;
            if (i == 3) continue;
            for (const char *p = REF_PARTS[i]; *p; p++) up[k++] = (char)(*p >= 'a' && *p <= 'z' ? *p - 32 : *p);
            up[k] = 0;
            rc = feed(up);
            used++;
        }
        CHECK(rc == (long)n && !memcmp(ur_decoder_message(), expect, n) && used == 16,
              "multipart uppercase, reversed, one dropped (%d parts)", used);
    }

    /* rejected parts leave the decoder state intact */
    {
        char bad[256];
        ur_decoder_reset(work, sizeof(work));
        CHECK(feed(REF_PARTS[0]) == 0, "first part");
        strcpy(bad, REF_PARTS[1]);
        bad[strlen(bad) - 1] ^= 1;
        CHECK(feed(bad) == UR_ERR_BYTEWORDS, "corrupted part");
        CHECK(feed("ur:psbt/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh")
              == UR_ERR_MISMATCH, "type change");
        CHECK(feed("xr:bytes/1-9/aeadaolazmjendeoti") == UR_ERR_SCHEME, "scheme");
        CHECK(feed("ur:bytes/2-8/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz")
              == UR_ERR_PART, "sequence component disagrees with the part");
        unsigned expected, received;
        ur_decoder_progress(&expected, &received);
        CHECK(expected == 9 && received == 1, "progress kept after rejections (%u/%u)", received, expected);
        long rc = 0;
        for (int i = 1; i < 9 && rc == 0; i++) rc = feed(REF_PARTS[i]);
        CHECK(rc == (long)make_message_cbor(expect, 256) && !memcmp(ur_decoder_message(), expect, (size_t)rc),
              "completes after rejections");
    }

    /* a work buffer too small for the padded fragments is rejected, not overrun */
    ur_decoder_reset(work, 200);
    CHECK(feed(REF_PARTS[0]) == UR_ERR_LIMIT, "work buffer limit");

    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
