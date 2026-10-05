#include "tx.h"
#include "sha256.h"
#include "reader.h"

int tx_parse(const uint8_t *raw, size_t len, const tx_visitor_t *v, tx_info_t *info) {
    rd_t r = {raw, len, 0, 0};
    sha256_ctx h;
    size_t io_start, io_end;
    int segwit = 0;
    uint64_t n;

    info->version = (int32_t)rd_le(&r, 4);
    if (len >= 6 && raw[4] == 0 && raw[5] == 1) {
        segwit = 1;
        r.pos += 2;
    }
    info->segwit = (uint8_t)segwit;
    io_start = r.pos;
    n = rd_varint(&r);
    if (n == 0 || n > UINT32_MAX) return 0;
    info->n_inputs = (uint32_t)n;
    for (uint32_t i = 0; i < info->n_inputs && !r.err; i++) {
        const uint8_t *prevout = rd_take(&r, 36);
        size_t script_sig_len = (size_t)rd_varint(&r);
        rd_take(&r, script_sig_len);
        uint32_t seq = (uint32_t)rd_le(&r, 4);
        if (!r.err && v && v->on_input && !v->on_input(v->ctx, i, prevout, script_sig_len, seq)) return 0;
    }
    n = rd_varint(&r);
    if (n > UINT32_MAX) return 0;
    info->n_outputs = (uint32_t)n;
    for (uint32_t i = 0; i < info->n_outputs && !r.err; i++) {
        uint64_t amount = rd_le(&r, 8);
        size_t spk_len = (size_t)rd_varint(&r);
        const uint8_t *spk = rd_take(&r, spk_len);
        if (!r.err && v && v->on_output && !v->on_output(v->ctx, i, amount, spk, spk_len)) return 0;
    }
    io_end = r.pos;
    for (uint32_t i = 0; segwit && i < info->n_inputs && !r.err; i++)
        for (uint64_t k = rd_varint(&r); k && !r.err; k--) rd_take(&r, rd_varint(&r));
    info->locktime = (uint32_t)rd_le(&r, 4);
    if (r.err || r.pos != len) return 0;

    sha256_init(&h);
    sha256_update(&h, raw, 4);
    sha256_update(&h, raw + io_start, io_end - io_start);
    sha256_update(&h, raw + len - 4, 4);
    sha256d_final(&h, info->txid);
    return 1;
}
