#ifndef CORE_TX_H
#define CORE_TX_H

#include <stddef.h>
#include <stdint.h>

/* Walks a serialized transaction once, calling back per input and output. Scripts are not interpreted.
 * The txid is the SHA256d of the non-witness serialization (internal byte order). */
typedef struct {
    int (*on_input)(void *ctx, uint32_t index, const uint8_t prevout[36], size_t script_sig_len, uint32_t sequence);
    int (*on_output)(void *ctx, uint32_t index, uint64_t amount, const uint8_t *spk, size_t spk_len);
    void *ctx;
} tx_visitor_t;

typedef struct {
    int32_t version;
    uint32_t locktime, n_inputs, n_outputs;
    uint8_t segwit; /* serialized with the marker / flag */
    uint8_t txid[32];
} tx_info_t;

int tx_parse(const uint8_t *raw, size_t len, const tx_visitor_t *v, tx_info_t *info);

#endif
