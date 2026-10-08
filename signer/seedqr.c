/* Reads a SeedQR back into a mnemonic. This carries the secret itself, so it is
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
static int checksum_ok(const uint16_t *idx, unsigned n) {
    uint8_t ent[32], hash[32];
    unsigned ent_bits = n * 11 - n / 3, cs_bits = n / 3;
    int ok = 1;

    memset(ent, 0, sizeof(ent));
    for (unsigned i = 0; i < ent_bits; i++) ent[i / 8] |= (uint8_t)((idx[i / 11] >> (10 - i % 11) & 1) << (7 - i % 8));
    sha256_of(ent, ent_bits / 8, hash);
    for (unsigned i = 0; i < cs_bits; i++) {
        unsigned want = hash[0] >> (7 - i) & 1, got = idx[n - 1] >> (10 - (ent_bits % 11 + i)) & 1;
        ok &= want == got;
    }
    wipe(ent, sizeof(ent));
    wipe(hash, sizeof(hash));
    return ok;
}

static int check_and_build(const uint16_t *idx, unsigned n, char *out, size_t cap) {
    size_t len = 0;

    if (!checksum_ok(idx, n)) return 0;
    for (unsigned i = 0; i < n; i++) {
        size_t w = strnlen(bip39_words[idx[i]], 8);
        if (len + w + 1 >= cap) return 0;
        if (i) out[len++] = ' ';
        memcpy(out + len, bip39_words[idx[i]], w);
        len += w;
    }
    out[len] = 0;
    return (int)len;
}

/* The list is sorted, and NUL padding sorts before any letter, so comparing all eight bytes keeps it
 * sorted. Only a-z is let through, so a word padded with NUL cannot match a shorter one */
static int word_index(const uint8_t *w, size_t len) {
    char key[8] = {0};
    int lo = 0, hi = 2047, found = -1;
    for (size_t i = 0; i < len && len <= 8; i++) {
        if (w[i] < 'a' || w[i] > 'z') hi = -1;
        key[i] = (char)w[i];
    }
    while (len && len <= 8 && found < 0 && lo <= hi) {
        int mid = (lo + hi) / 2, c = memcmp(key, bip39_words[mid], 8);
        if (!c) found = mid;
        else if (c < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    wipe(key, sizeof(key));
    return found;
}

size_t bip39_normalize(const uint8_t *in, size_t len, uint8_t *out) {
    size_t n = 0;
    int gap = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = in[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            gap = n > 0;
            continue;
        }
        if (gap) out[n++] = ' ', gap = 0;
        out[n++] = c >= 'A' && c <= 'Z' ? (uint8_t)(c + 32) : c;
    }
    return n;
}

int bip39_mnemonic_ok(const uint8_t *mn, size_t len) {
    uint16_t idx[24];
    unsigned n = 0;
    size_t start = 0;
    int ok = 0;

    for (size_t i = 0; i <= len; i++) {
        if (i < len && mn[i] != ' ') continue;
        int v = n < 24 ? word_index(mn + start, i - start) : -1;
        if (v < 0) goto done;
        idx[n++] = (uint16_t)v;
        start = i + 1;
    }
    ok = n % 3 == 0 && n >= 12 && checksum_ok(idx, n);
done:
    wipe(idx, sizeof(idx));
    return ok;
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
                unsigned bit = b < ent_bits ? payload[b / 8] >> (7 - b % 8) & 1 : hash[0] >> (7 - (b - ent_bits)) & 1;
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
