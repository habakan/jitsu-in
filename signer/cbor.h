#ifndef CORE_CBOR_H
#define CORE_CBOR_H

/* Just enough CBOR to describe public keys as BCR-2020-007 / -010 / -015 do, for crypto-account and
 * crypto-output URs. Canonical: shortest heads, map keys ascending */

#include <stddef.h>
#include <stdint.h>

enum { CBOR_UINT = 0, CBOR_BYTES = 2, CBOR_ARRAY = 4, CBOR_MAP = 5, CBOR_TAG = 6, CBOR_SIMPLE = 7 };

typedef struct {
    uint8_t *b;
    size_t n, cap; /* n past cap means it did not fit */
} cbor_t;

void cbor_head(cbor_t *c, unsigned major, uint64_t v);
/* crypto-hdkey (tag 303) for an xpub as serialized, with its origin as crypto-keypath (304) */
void cbor_hdkey(cbor_t *c, const uint8_t ser[78], uint32_t fingerprint, const uint32_t *path, unsigned depth,
                int testnet);

#endif
