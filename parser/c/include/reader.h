#ifndef CORE_READER_H
#define CORE_READER_H

/* Reads untrusted bytes. Lengths are checked against what remains before reading; errors accumulate in err */

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *p;
    size_t n, pos;
    int err;
} rd_t;

static inline const uint8_t *rd_take(rd_t *r, size_t k) {
    if (r->err || k > r->n - r->pos) {
        r->err = 1;
        return NULL;
    }
    r->pos += k;
    return r->p + r->pos - k;
}

static inline uint64_t rd_le(rd_t *r, int k) {
    const uint8_t *b = rd_take(r, (size_t)k);
    uint64_t v = 0;
    for (int i = k - 1; b && i >= 0; i--) v = v << 8 | b[i];
    return v;
}

/* compact size. Rejects values larger than the remaining bytes and non-minimal encodings */
static inline uint64_t rd_varint(rd_t *r) {
    uint64_t v = rd_le(r, 1);
    if (v == 0xfd) {
        v = rd_le(r, 2);
        if (v < 0xfd) r->err = 1;
    } else if (v == 0xfe) {
        v = rd_le(r, 4);
        if (v <= 0xffff) r->err = 1;
    } else if (v == 0xff) {
        v = rd_le(r, 8);
        if (v <= 0xffffffff) r->err = 1;
    }
    if (v > r->n - r->pos) r->err = 1;
    return r->err ? 0 : v;
}

#endif
