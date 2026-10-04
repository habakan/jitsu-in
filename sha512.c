#include "sha512.h"
#include <string.h>
#include "wipe.h"

static const uint64_t K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static uint64_t load_be(const unsigned char *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static void store_be(unsigned char *p, uint64_t v) {
    for (int i = 7; i >= 0; i--, v >>= 8) p[i] = (unsigned char)v;
}

#ifdef SHA512_HOST_COMPRESS
/* 64-bit arithmetic runs about 25x slower in the rv32 WASM interpreter, so only the compression
 * function is handed to the host */
__attribute__((import_module("env"), import_name("host_sha512_compress")))
void host_sha512_compress(uint64_t *s, const unsigned char *block);
#define compress host_sha512_compress
#else
#define compress sha512_compress
#endif

void sha512_compress(uint64_t s[8], const unsigned char block[128]) {
    uint64_t w[80], a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (int i = 0; i < 16; i++) w[i] = load_be(block + 8 * i);
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ROR(w[i - 15], 1) ^ ROR(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROR(w[i - 2], 19) ^ ROR(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    for (int i = 0; i < 80; i++) {
        uint64_t t1 = h + (ROR(e, 14) ^ ROR(e, 18) ^ ROR(e, 41)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint64_t t2 = (ROR(a, 28) ^ ROR(a, 34) ^ ROR(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

void sha512_init(sha512_ctx *c) {
    static const uint64_t iv[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                   0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
    memcpy(c->s, iv, sizeof(iv));
    c->len = 0;
}

void sha512_update(sha512_ctx *c, const unsigned char *p, size_t n) {
    size_t used = c->len % 128;
    c->len += n;
    if (used) {
        size_t take = n < 128 - used ? n : 128 - used;
        memcpy(c->buf + used, p, take);
        p += take, n -= take, used += take;
        if (used < 128) return;
        compress(c->s, c->buf);
    }
    for (; n >= 128; p += 128, n -= 128) compress(c->s, p);
    memcpy(c->buf, p, n);
}

void sha512_final(sha512_ctx *c, unsigned char out[64]) {
    unsigned char pad[144] = {0x80};
    size_t used = c->len % 128, padlen = (used < 112 ? 112 : 240) - used;
    uint64_t bits = c->len * 8;
    store_be(pad + padlen + 8, bits);
    sha512_update(c, pad, padlen + 16);
    for (int i = 0; i < 8; i++) store_be(out + 8 * i, c->s[i]);
}

void hmac_sha512_init(hmac_sha512_ctx *h, const unsigned char *key, size_t keylen) {
    unsigned char k[128] = {0};
    if (keylen > 128) {  /* a 24-word mnemonic can be longer than 128 bytes */
        sha512_init(&h->inner);
        sha512_update(&h->inner, key, keylen);
        sha512_final(&h->inner, k);
    } else {
        memcpy(k, key, keylen);
    }
    for (int i = 0; i < 128; i++) k[i] ^= 0x36;
    sha512_init(&h->inner);
    sha512_update(&h->inner, k, 128);
    for (int i = 0; i < 128; i++) k[i] ^= 0x36 ^ 0x5c;
    sha512_init(&h->outer);
    sha512_update(&h->outer, k, 128);
    wipe(k, sizeof(k));
}

void hmac_sha512_final(hmac_sha512_ctx *h, unsigned char out[64]) {
    unsigned char t[64];
    sha512_final(&h->inner, t);
    sha512_update(&h->outer, t, 64);
    sha512_final(&h->outer, out);
    wipe(t, sizeof(t));
}

/* dklen fixed at 64 (one block) for BIP39. Reusing the state after the inner and outer pads halves
 * the number of compressions */
void pbkdf2_hmac_sha512(const unsigned char *pw, size_t pwlen, const unsigned char *salt, size_t saltlen,
                        unsigned iter, unsigned char out[64]) {
    hmac_sha512_ctx base, h;
    unsigned char u[64];
    static const unsigned char one[4] = {0, 0, 0, 1};
    hmac_sha512_init(&base, pw, pwlen);
    h = base;
    sha512_update(&h.inner, salt, saltlen);
    sha512_update(&h.inner, one, 4);
    hmac_sha512_final(&h, u);
    memcpy(out, u, 64);
    for (unsigned i = 1; i < iter; i++) {
        h = base;
        sha512_update(&h.inner, u, 64);
        hmac_sha512_final(&h, u);
        for (int j = 0; j < 64; j++) out[j] ^= u[j];
    }
    wipe(&base, sizeof(base));
    wipe(&h, sizeof(h));
    wipe(u, sizeof(u));
}
