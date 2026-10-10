#include "cbor.h"
#include <string.h>

void cbor_head(cbor_t *c, unsigned major, uint64_t v) {
    unsigned extra = v < 24 ? 0 : v < 0x100 ? 1 : v < 0x10000 ? 2 : v < 0x100000000ull ? 4 : 8;
    if (c->n + 1 + extra > c->cap) {
        c->n = c->cap + 1;
        return;
    }
    c->b[c->n++] = (uint8_t)(major << 5 | (extra == 0 ? v : extra == 1 ? 24 : extra == 2 ? 25 : extra == 4 ? 26 : 27));
    for (unsigned k = extra; k > 0; k--) c->b[c->n++] = (uint8_t)(v >> (8 * (k - 1)));
}

static void bytes(cbor_t *c, const uint8_t *p, size_t n) {
    cbor_head(c, CBOR_BYTES, n);
    if (c->n + n > c->cap) {
        c->n = c->cap + 1;
        return;
    }
    memcpy(c->b + c->n, p, n);
    c->n += n;
}

void cbor_hdkey(cbor_t *c, const uint8_t ser[78], uint32_t fingerprint, const uint32_t *path, unsigned depth,
                int testnet) {
    cbor_head(c, CBOR_TAG, 303);
    cbor_head(c, CBOR_MAP, testnet ? 5 : 4);
    cbor_head(c, CBOR_UINT, 3), bytes(c, ser + 45, 33);
    cbor_head(c, CBOR_UINT, 4), bytes(c, ser + 13, 32);
    if (testnet) { /* crypto-coininfo: bitcoin's testnet. Mainnet is the default and left out */
        cbor_head(c, CBOR_UINT, 5), cbor_head(c, CBOR_TAG, 305);
        cbor_head(c, CBOR_MAP, 1), cbor_head(c, CBOR_UINT, 2), cbor_head(c, CBOR_UINT, 1);
    }
    cbor_head(c, CBOR_UINT, 6), cbor_head(c, CBOR_TAG, 304), cbor_head(c, CBOR_MAP, 2);
    cbor_head(c, CBOR_UINT, 1), cbor_head(c, CBOR_ARRAY, 2 * depth);
    for (unsigned i = 0; i < depth; i++) {
        cbor_head(c, CBOR_UINT, path[i] & 0x7fffffffu);
        cbor_head(c, CBOR_SIMPLE, path[i] >> 31 ? 21 : 20);
    }
    cbor_head(c, CBOR_UINT, 2), cbor_head(c, CBOR_UINT, fingerprint);
    cbor_head(c, CBOR_UINT, 8);
    cbor_head(c, CBOR_UINT, (uint32_t)ser[5] << 24 | (uint32_t)ser[6] << 16 | (uint32_t)ser[7] << 8 | ser[8]);
}
