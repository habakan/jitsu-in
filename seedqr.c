/* Reads a SeedQR (SeedSigner's format) back into a mnemonic. This carries the secret itself, so it is
 * handled natively and never goes through the parser. The BIP39 checksum is always verified and
 * anything that fails it is refused.
 *
 * Standard SeedQR: four digits per word index (48 digits for 12 words, 96 for 24)
 * CompactSeedQR: the raw entropy (16 or 32 bytes) */
#include "seedqr.h"
#include <string.h>
#include "bip39_words.h"
#include "sha256.h"
#include "wipe.h"

static void sha256_of(const uint8_t *p, size_t n, uint8_t out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, p, n);
    sha256_final(&c, out);
}

/* Take 11 bits per word index back into entropy and checksum, then verify it with SHA-256 */
static int check_and_build(const uint16_t *idx, unsigned n, char *out, size_t cap) {
    uint8_t ent[32], hash[32];
    unsigned ent_bits = n * 11 - n / 3, ent_len = ent_bits / 8, cs_bits = n / 3;
    size_t len = 0;
    int ok;

    memset(ent, 0, sizeof(ent));
    for (unsigned i = 0; i < n * 11; i++) {
        unsigned bit = idx[i / 11] >> (10 - i % 11) & 1;
        if (i < ent_bits) ent[i / 8] |= (uint8_t)(bit << (7 - i % 8));
    }
    sha256_of(ent, ent_len, hash);
    ok = 1;
    for (unsigned i = 0; i < cs_bits; i++) {
        unsigned want = hash[0] >> (7 - i) & 1, got = idx[n - 1] >> (10 - (ent_bits % 11 + i)) & 1;
        ok &= want == got;
    }

    for (unsigned i = 0; ok && i < n; i++) {
        size_t w = strlen(bip39_words[idx[i]]);
        if (len + w + 1 >= cap) return wipe(ent, sizeof(ent)), 0;
        if (i) out[len++] = ' ';
        memcpy(out + len, bip39_words[idx[i]], w);
        len += w;
    }
    out[len] = 0;
    wipe(ent, sizeof(ent));
    wipe(hash, sizeof(hash));
    return ok ? (int)len : 0;
}

int seedqr_decode(const uint8_t *payload, size_t len, char *out, size_t cap) {
    uint16_t idx[24];
    unsigned n;
    int r;

    if (len == 48 || len == 96) { /* standard SeedQR: four digits per index */
        n = (unsigned)len / 4;
        for (unsigned i = 0; i < n; i++) {
            unsigned v = 0;
            for (unsigned k = 0; k < 4; k++) {
                uint8_t c = payload[i * 4 + k];
                if (c < '0' || c > '9') return 0;
                v = v * 10 + (unsigned)(c - '0');
            }
            if (v > 2047) return 0;
            idx[i] = (uint16_t)v;
        }
    } else if (len == 16 || len == 32) { /* CompactSeedQR: the raw entropy */
        uint8_t hash[32];
        unsigned ent_bits = (unsigned)len * 8;
        n = ent_bits / 32 * 3;
        sha256_of(payload, len, hash);
        for (unsigned i = 0; i < n; i++) {
            unsigned v = 0;
            for (unsigned k = 0; k < 11; k++) {
                unsigned b = i * 11 + k;
                unsigned bit = b < ent_bits ? payload[b / 8] >> (7 - b % 8) & 1
                                            : hash[0] >> (7 - (b - ent_bits)) & 1;
                v = v << 1 | bit;
            }
            idx[i] = (uint16_t)v;
        }
        wipe(hash, sizeof(hash));
    } else {
        return 0;
    }
    r = check_and_build(idx, n, out, cap);
    wipe(idx, sizeof(idx));
    return r;
}
