/* Exposes the C's tx parser and SHA-256 with the same shape the Rust port exports, so that
 * tools/check_rust_agrees.mjs can require the two to give the same answer. Test-only: it is not
 * part of parser.wasm. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "tx.h"

#define IN_CAP 32768
#define MAX_OUT 16

typedef struct {
    int32_t version;
    uint32_t locktime, n_inputs, n_outputs, segwit;
    uint8_t txid[32];
    uint64_t amounts[MAX_OUT];
    uint32_t spk_off[MAX_OUT], spk_len[MAX_OUT];
} probe_out_t;

static uint8_t in_buf[IN_CAP];
static probe_out_t out;

__attribute__((export_name("probe_input"))) uint8_t *probe_input(void) { return in_buf; }
__attribute__((export_name("probe_tx_out"))) const probe_out_t *probe_tx_out(void) { return &out; }

static int on_output(void *ctx, uint32_t i, uint64_t amount, const uint8_t *spk, size_t spk_len) {
    (void)ctx;
    if (i < MAX_OUT) {
        out.amounts[i] = amount;
        out.spk_off[i] = (uint32_t)(spk - in_buf);
        out.spk_len[i] = (uint32_t)spk_len;
    }
    return 1;
}

__attribute__((export_name("probe_tx_parse"))) int probe_tx_parse(uint32_t len) {
    tx_info_t info;
    tx_visitor_t v = {0};
    if (len > IN_CAP) return 0;
    memset(&out, 0, sizeof(out));
    memset(&info, 0, sizeof(info));
    v.on_output = on_output;
    if (!tx_parse(in_buf, len, &v, &info)) return 0;
    out.version = info.version;
    out.locktime = info.locktime;
    out.n_inputs = info.n_inputs;
    out.n_outputs = info.n_outputs;
    out.segwit = info.segwit;
    memcpy(out.txid, info.txid, 32);
    return 1;
}

__attribute__((export_name("probe_sha256"))) int probe_sha256(uint32_t len) {
    uint8_t digest[32];
    if (len > IN_CAP) return 0;
    sha256(in_buf, len, digest);
    memcpy(in_buf, digest, 32);
    return 1;
}
