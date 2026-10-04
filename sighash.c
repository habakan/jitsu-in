#include "sighash.h"
#include <string.h>
#include "hash.h"

static void put_le(uint8_t *b, uint64_t v, int k) {
    for (int i = 0; i < k; i++, v >>= 8) b[i] = (uint8_t)v;
}

static void h_le(sha256_ctx *h, uint64_t v, int k) {
    uint8_t b[8];
    put_le(b, v, k);
    sha256_update(h, b, (size_t)k);
}

/* PLAN_MAX_SPK < 0xfd, so a compact size here is always one byte */
static void h_script(sha256_ctx *h, const plan_script_t *s) {
    sha256_update(h, &s->len, 1);
    sha256_update(h, s->bytes, s->len);
}

static void h_outpoint(sha256_ctx *h, const plan_input_t *in) {
    sha256_update(h, in->prev_txid, 32);
    h_le(h, in->prev_vout, 4);
}

static void h_output(sha256_ctx *h, const plan_output_t *o) {
    h_le(h, o->amount, 8);
    h_script(h, &o->spk);
}

int sighash_bip143_p2wpkh(const plan_t *p, unsigned index, uint8_t out[32]) {
    const plan_input_t *in = &p->inputs[index];
    uint8_t prevouts[32], sequences[32], outputs[32];
    static const uint8_t code_head[4] = {0x19, 0x76, 0xa9, 0x14}, code_tail[2] = {0x88, 0xac};
    sha256_ctx h;

    if (index >= p->n_inputs || in->spk.len != 22 || in->spk.bytes[0] != 0 || in->spk.bytes[1] != 20) return 0;
    sha256_init(&h);
    for (unsigned i = 0; i < p->n_inputs; i++) h_outpoint(&h, &p->inputs[i]);
    sha256d_final(&h, prevouts);
    sha256_init(&h);
    for (unsigned i = 0; i < p->n_inputs; i++) h_le(&h, p->inputs[i].sequence, 4);
    sha256d_final(&h, sequences);
    sha256_init(&h);
    for (unsigned i = 0; i < p->n_outputs; i++) h_output(&h, &p->outputs[i]);
    sha256d_final(&h, outputs);

    sha256_init(&h);
    h_le(&h, (uint32_t)p->tx_version, 4);
    sha256_update(&h, prevouts, 32);
    sha256_update(&h, sequences, 32);
    h_outpoint(&h, in);
    sha256_update(&h, code_head, 4);
    sha256_update(&h, in->spk.bytes + 2, 20);
    sha256_update(&h, code_tail, 2);
    h_le(&h, in->amount, 8);
    h_le(&h, in->sequence, 4);
    sha256_update(&h, outputs, 32);
    h_le(&h, p->locktime, 4);
    h_le(&h, 1, 4);
    sha256d_final(&h, out);
    return 1;
}

int sighash_bip341_keypath(const secp256k1_context *ctx, const plan_t *p, unsigned index, uint8_t hash_type,
                           uint8_t out[32]) {
    /* epoch(1) + hash_type(1) + version/locktime(8) + sha_*(5x32) + spend_type(1) + input(at most 36+8+84+4) + single(32) */
    uint8_t msg[1 + 1 + 8 + 160 + 1 + 132 + 32], d[32];
    size_t n = 0;
    int acp = hash_type & 0x80, out_type = hash_type & 3;
    const plan_input_t *in = &p->inputs[index];
    sha256_ctx h;

    if (index >= p->n_inputs || (hash_type > 3 && (hash_type < 0x81 || hash_type > 0x83))) return 0;
    if (out_type == 3 && index >= p->n_outputs) return 0;
    msg[n++] = 0;
    msg[n++] = hash_type;
    put_le(msg + n, (uint32_t)p->tx_version, 4), n += 4;
    put_le(msg + n, p->locktime, 4), n += 4;
    if (!acp) {
        sha256_init(&h);
        for (unsigned i = 0; i < p->n_inputs; i++) h_outpoint(&h, &p->inputs[i]);
        sha256_final(&h, msg + n), n += 32;
        sha256_init(&h);
        for (unsigned i = 0; i < p->n_inputs; i++) h_le(&h, p->inputs[i].amount, 8);
        sha256_final(&h, msg + n), n += 32;
        sha256_init(&h);
        for (unsigned i = 0; i < p->n_inputs; i++) h_script(&h, &p->inputs[i].spk);
        sha256_final(&h, msg + n), n += 32;
        sha256_init(&h);
        for (unsigned i = 0; i < p->n_inputs; i++) h_le(&h, p->inputs[i].sequence, 4);
        sha256_final(&h, msg + n), n += 32;
    }
    if (out_type != 2 && out_type != 3) {
        sha256_init(&h);
        for (unsigned i = 0; i < p->n_outputs; i++) h_output(&h, &p->outputs[i]);
        sha256_final(&h, msg + n), n += 32;
    }
    msg[n++] = 0; /* spend_type: key path, no annex */
    if (acp) {
        memcpy(msg + n, in->prev_txid, 32), n += 32;
        put_le(msg + n, in->prev_vout, 4), n += 4;
        put_le(msg + n, in->amount, 8), n += 8;
        msg[n++] = in->spk.len;
        memcpy(msg + n, in->spk.bytes, in->spk.len), n += in->spk.len;
        put_le(msg + n, in->sequence, 4), n += 4;
    } else {
        put_le(msg + n, index, 4), n += 4;
    }
    if (out_type == 3) {
        sha256_init(&h);
        h_output(&h, &p->outputs[index]);
        sha256_final(&h, d);
        memcpy(msg + n, d, 32), n += 32;
    }
    return secp256k1_tagged_sha256(ctx, out, (const uint8_t *)"TapSighash", 10, msg, n);
}
