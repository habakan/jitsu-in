/* SeedQR（SeedSigner 互換）を読んでニーモニックに戻す。これは秘密そのものを運ぶので、解析器（WASM）には
 * 渡さずネイティブ側で扱う。BIP39 のチェックサムを必ず確かめ、合わないものは受け取らない。
 *
 * 標準 SeedQR: 単語の番号を 4 桁ずつ並べた数字列（12 語なら 48 桁、24 語なら 96 桁）
 * CompactSeedQR: エントロピーのバイト列そのもの（16 または 32 byte） */
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

/* 単語の番号から 11bit ずつ取り出してエントロピーとチェックサムに戻し、SHA-256 で検算する */
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

    if (len == 48 || len == 96) { /* 標準 SeedQR: 4 桁ずつの番号 */
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
    } else if (len == 16 || len == 32) { /* CompactSeedQR: エントロピーそのもの */
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
