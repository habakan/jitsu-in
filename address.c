#include "address.h"
#include <string.h>
#include "hash.h"

static const char B32[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const char B58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static uint32_t polymod_step(uint32_t c, uint8_t v) {
    uint32_t b = c >> 25;
    c = (c & 0x1ffffff) << 5 ^ v;
    if (b & 1) c ^= 0x3b6a57b2;
    if (b & 2) c ^= 0x26508e6d;
    if (b & 4) c ^= 0x1ea119fa;
    if (b & 8) c ^= 0x3d4233dd;
    if (b & 16) c ^= 0x2a1462b3;
    return c;
}

static void bech32_encode(const char *hrp, const uint8_t *data, size_t n, uint32_t constant, char *out) {
    uint32_t c = 1;
    size_t hl = strlen(hrp), o = 0;
    for (size_t i = 0; i < hl; i++) c = polymod_step(c, (uint8_t)(hrp[i] >> 5));
    c = polymod_step(c, 0);
    for (size_t i = 0; i < hl; i++) c = polymod_step(c, hrp[i] & 31);
    memcpy(out, hrp, hl), o = hl;
    out[o++] = '1';
    for (size_t i = 0; i < n; i++) c = polymod_step(c, data[i]), out[o++] = B32[data[i]];
    for (int i = 0; i < 6; i++) c = polymod_step(c, 0);
    c ^= constant;
    for (int i = 0; i < 6; i++) out[o++] = B32[(c >> (5 * (5 - i))) & 31];
    out[o] = 0;
}

/* 末尾に 4 byte のチェックサムを足して base58 にする。アドレス（21 byte）と xpub（78 byte）で使う */
void base58check_data(const uint8_t *p, size_t n, char *out) {
    uint8_t buf[BASE58CHECK_MAX_IN + 4], chk[32], digits[BASE58CHECK_MAX_OUT] = {0};
    size_t nd = 0, o = 0;
    sha256_ctx h;

    if (n > BASE58CHECK_MAX_IN) return (void)(out[0] = 0);
    memcpy(buf, p, n);
    sha256_init(&h);
    sha256_update(&h, buf, n);
    sha256d_final(&h, chk);
    memcpy(buf + n, chk, 4);
    for (size_t i = 0; i < n + 4; i++) {
        uint32_t carry = buf[i];
        for (size_t j = 0; j < nd; j++) {
            carry += (uint32_t)digits[j] << 8;
            digits[j] = carry % 58;
            carry /= 58;
        }
        for (; carry; carry /= 58) digits[nd++] = carry % 58;
    }
    for (size_t i = 0; i < n + 4 && buf[i] == 0; i++) out[o++] = '1';
    while (nd) out[o++] = B58[digits[--nd]];
    out[o] = 0;
}

static void base58check(uint8_t version, const uint8_t hash[20], char *out) {
    uint8_t buf[21];
    buf[0] = version;
    memcpy(buf + 1, hash, 20);
    base58check_data(buf, sizeof(buf), out);
}

int address_encode(const uint8_t *spk, size_t len, int testnet, char out[ADDRESS_MAX]) {
    out[0] = 0;
    if (len == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 20 && spk[23] == 0x88 && spk[24] == 0xac) {
        base58check(testnet ? 0x6f : 0x00, spk + 3, out);
        return 1;
    }
    if (len == 23 && spk[0] == 0xa9 && spk[1] == 20 && spk[22] == 0x87) {
        base58check(testnet ? 0xc4 : 0x05, spk + 2, out);
        return 1;
    }
    /* witness program: OP_0 か OP_1〜OP_16 の後に 2〜40 byte の push が 1 個だけ */
    if (len >= 4 && len <= 42 && (spk[0] == 0 || (spk[0] >= 0x51 && spk[0] <= 0x60)) && spk[1] == len - 2) {
        uint8_t ver = spk[0] ? (uint8_t)(spk[0] - 0x50) : 0, data[1 + 65];
        size_t n = 0, bits = 0;
        uint32_t acc = 0;
        if (ver == 0 && len != 22 && len != 34) return 0;
        data[n++] = ver;
        for (size_t i = 2; i < len; i++) {
            acc = acc << 8 | spk[i], bits += 8;
            for (; bits >= 5; bits -= 5) data[n++] = (acc >> (bits - 5)) & 31;
        }
        if (bits) data[n++] = (acc << (5 - bits)) & 31;
        bech32_encode(testnet ? "tb" : "bc", data, n, ver ? 0x2bc830a3 : 1, out);
        return 1;
    }
    return 0;
}
