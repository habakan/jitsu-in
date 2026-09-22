/* Turns a PSBT v0 (BIP174) into a plan_t and inserts the signer's signatures into the PSBT.
 * Holds no keys and has no imports (built for WASM, it cannot call a single host function) */

#include <string.h>
#include "psbt_parser.h"
#include "reader.h"
#include "tx.h"
#include "ur.h"

#ifdef __wasm__
#define EXPORT(name) __attribute__((export_name(#name))) name
#else
#define EXPORT(name) name
#endif

#define MAX_KV 64

static uint8_t in_buf[PSBT_MAX], out_buf[PSBT_OUT_MAX];
static size_t in_len;
static plan_t plan;
static plan_sig_t sigs[PLAN_MAX_INPUTS];
static uint32_t prevtx_off[PLAN_MAX_INPUTS], prevtx_len[PLAN_MAX_INPUTS];
static size_t in_map_end[PLAN_MAX_INPUTS];
static int parsed;

typedef struct {
    const uint8_t *key, *val;
    size_t klen, vlen;
} kv_t;

typedef struct {
    int found;
    uint8_t depth;
    uint32_t path[PLAN_MAX_DEPTH];
    const uint8_t *pubkey; /* key of the BIP32_DERIVATION entry (33 bytes); used to detect an existing signature */
} cand_t;

static uint32_t le32(const uint8_t *b) {
    return b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

/* fingerprint(4) + path(4 x n). The first entry with our fingerprint and a depth that fits becomes the candidate */
static int keypath(const uint8_t *v, size_t n, uint32_t fp, cand_t *c) {
    size_t depth;
    if (n < 4 || (n - 4) % 4) return 0;
    depth = (n - 4) / 4;
    /* The fingerprint bytes (display order) are compared as a big-endian integer; path elements are little-endian */
    if (c->found || ((uint32_t)v[0] << 24 | (uint32_t)v[1] << 16 | (uint32_t)v[2] << 8 | v[3]) != fp
        || depth > PLAN_MAX_DEPTH)
        return 1;
    c->found = 1;
    c->depth = (uint8_t)depth;
    for (size_t i = 0; i < depth; i++) c->path[i] = le32(v + 4 + 4 * i);
    return 1;
}

/* TAP_BIP32_DERIVATION value: leaf hash count, leaf hashes, keypath. Only key-path entries (no leaves) qualify */
static int tap_keypath(const uint8_t *v, size_t n, uint32_t fp, cand_t *c) {
    rd_t r = {v, n, 0, 0};
    uint64_t leaves = rd_varint(&r);
    if (r.err || leaves > (n - r.pos) / 32) return 0;
    rd_take(&r, 32 * (size_t)leaves);
    if (leaves) {
        cand_t ignore = {0};
        return keypath(v + r.pos, n - r.pos, fp, &ignore);
    }
    return keypath(v + r.pos, n - r.pos, fp, c);
}

static int read_map(rd_t *r, kv_t *kv, size_t *n, size_t *end) {
    *n = 0;
    for (;;) {
        size_t klen = (size_t)rd_varint(r);
        if (r->err) return P_ERR_FORMAT;
        if (klen == 0) {
            *end = r->pos - 1;
            return P_OK;
        }
        if (*n == MAX_KV) return P_ERR_LIMIT;
        kv_t *e = &kv[(*n)++];
        e->klen = klen;
        e->key = rd_take(r, klen);
        e->vlen = (size_t)rd_varint(r);
        e->val = rd_take(r, e->vlen);
        if (r->err) return P_ERR_FORMAT;
        for (size_t i = 0; i + 1 < *n; i++)
            if (kv[i].klen == klen && !memcmp(kv[i].key, e->key, klen)) return P_ERR_DUPLICATE;
    }
}

static int set_script(plan_script_t *s, const uint8_t *b, size_t n) {
    if (n > PLAN_MAX_SPK) return 0;
    s->len = (uint8_t)n;
    memcpy(s->bytes, b, n);
    return 1;
}

static int is_p2wpkh(const plan_script_t *s) { return s->len == 22 && s->bytes[0] == 0 && s->bytes[1] == 20; }
static int is_p2tr(const plan_script_t *s) { return s->len == 34 && s->bytes[0] == 0x51 && s->bytes[1] == 32; }

typedef struct {
    int bad_script_sig, too_many, bad_spk;
} utx_ctx_t;

static int utx_in(void *c, uint32_t i, const uint8_t prevout[36], size_t script_sig_len, uint32_t seq) {
    utx_ctx_t *u = c;
    if (i >= PLAN_MAX_INPUTS) return u->too_many = 1, 0;
    if (script_sig_len) u->bad_script_sig = 1;
    memcpy(plan.inputs[i].prev_txid, prevout, 32);
    plan.inputs[i].prev_vout = le32(prevout + 32);
    plan.inputs[i].sequence = seq;
    return 1;
}

static int utx_out(void *c, uint32_t i, uint64_t amount, const uint8_t *spk, size_t len) {
    utx_ctx_t *u = c;
    if (i >= PLAN_MAX_OUTPUTS) return u->too_many = 1, 0;
    plan.outputs[i].amount = amount;
    if (!set_script(&plan.outputs[i].spk, spk, len)) return u->bad_spk = 1, 0;
    return 1;
}

typedef struct {
    uint32_t vout;
    int found;
    plan_input_t *in;
} prev_ctx_t;

static int prev_out(void *c, uint32_t i, uint64_t amount, const uint8_t *spk, size_t len) {
    prev_ctx_t *p = c;
    if (i != p->vout) return 1;
    p->found = 1;
    p->in->amount = amount;
    return set_script(&p->in->spk, spk, len);
}

static int parse_global(rd_t *r) {
    kv_t kv[MAX_KV];
    size_t n, end;
    int rc = read_map(r, kv, &n, &end), have_tx = 0;
    if (rc) return rc;
    /* Check the version before v2-only keys so that v2 is reported as unsupported, not malformed */
    for (size_t i = 0; i < n; i++) {
        if (kv[i].key[0] != 0xfb) continue;
        if (kv[i].klen != 1 || kv[i].vlen != 4) return P_ERR_FORMAT;
        if (le32(kv[i].val) != 0) return P_ERR_UNSUPPORTED;
    }
    for (size_t i = 0; i < n; i++) {
        uint8_t t = kv[i].key[0];
        if (t == 0x00) {
            utx_ctx_t u = {0};
            tx_visitor_t v = {utx_in, utx_out, &u};
            tx_info_t info;
            if (kv[i].klen != 1) return P_ERR_FORMAT;
            if (!tx_parse(kv[i].val, kv[i].vlen, &v, &info))
                return u.too_many ? P_ERR_LIMIT : u.bad_spk ? P_ERR_UNSUPPORTED : P_ERR_TX;
            if (u.bad_script_sig || info.segwit || info.n_outputs == 0) return P_ERR_TX;
            plan.tx_version = info.version;
            plan.locktime = info.locktime;
            plan.n_inputs = (uint8_t)info.n_inputs;
            plan.n_outputs = (uint8_t)info.n_outputs;
            have_tx = 1;
        } else if (t == 0x01) {
            cand_t ignore = {0};
            if (kv[i].klen != 79 || !keypath(kv[i].val, kv[i].vlen, 0, &ignore)) return P_ERR_FORMAT;
        } else if (t >= 0x02 && t <= 0x06) {
            return P_ERR_FORMAT; /* PSBT v2 only */
        }
    }
    return have_tx ? P_OK : P_ERR_TX;
}

static int parse_input(rd_t *r, unsigned idx, uint32_t fp) {
    kv_t kv[MAX_KV];
    size_t n;
    plan_input_t *in = &plan.inputs[idx];
    const kv_t *wu = NULL, *nwu = NULL;
    cand_t bip32 = {0}, tap = {0};
    int finalized = 0, has_tapsig = 0, has_merkle = 0, signed_by_cand = 0;
    uint32_t sighash = 0xffffffffu;
    int rc = read_map(r, kv, &n, &in_map_end[idx]);
    if (rc) return rc;

    for (size_t i = 0; i < n; i++) {
        const kv_t *e = &kv[i];
        switch (e->key[0]) {
        case 0x00: if (e->klen != 1) return P_ERR_FORMAT; nwu = e; break;
        case 0x01: if (e->klen != 1) return P_ERR_FORMAT; wu = e; break;
        case 0x02: if (e->klen != 34 && e->klen != 66) return P_ERR_FORMAT; break;
        case 0x03:
            if (e->klen != 1 || e->vlen != 4) return P_ERR_FORMAT;
            sighash = le32(e->val);
            break;
        case 0x04: case 0x05: if (e->klen != 1) return P_ERR_FORMAT; break;
        case 0x06: {
            cand_t ignore = {0}; /* uncompressed keys cannot be used for P2WPKH; only validate the format */
            if ((e->klen != 34 && e->klen != 66) || !keypath(e->val, e->vlen, fp, e->klen == 34 ? &bip32 : &ignore))
                return P_ERR_FORMAT;
            if (bip32.found && !bip32.pubkey) bip32.pubkey = e->key + 1;
            break;
        }
        case 0x07: case 0x08: if (e->klen != 1) return P_ERR_FORMAT; finalized = 1; break;
        case 0x0e: case 0x0f: case 0x10: case 0x11: case 0x12: return P_ERR_FORMAT; /* PSBT v2 only */
        case 0x13:
            if (e->klen != 1 || (e->vlen != 64 && e->vlen != 65)) return P_ERR_FORMAT;
            has_tapsig = 1;
            break;
        case 0x14: if (e->klen != 65 || (e->vlen != 64 && e->vlen != 65)) return P_ERR_FORMAT; break;
        case 0x15: if (e->klen < 34 || (e->klen - 34) % 32) return P_ERR_FORMAT; break; /* control block is 33 + 32m */
        case 0x16:
            if (e->klen != 33 || !tap_keypath(e->val, e->vlen, fp, &tap)) return P_ERR_FORMAT;
            break;
        case 0x17: if (e->klen != 1 || e->vlen != 32) return P_ERR_FORMAT; break;
        case 0x18: if (e->klen != 1 || e->vlen != 32) return P_ERR_FORMAT; has_merkle = 1; break;
        default: break;
        }
    }
    for (size_t i = 0; bip32.pubkey && i < n; i++)
        if (kv[i].key[0] == 0x02 && kv[i].klen == 34 && !memcmp(kv[i].key + 1, bip32.pubkey, 33)) signed_by_cand = 1;

    if (nwu) {
        prev_ctx_t pc = {in->prev_vout, 0, in};
        tx_visitor_t v = {NULL, prev_out, &pc};
        tx_info_t info;
        if (!tx_parse(nwu->val, nwu->vlen, &v, &info)) return P_ERR_UTXO;
        if (!pc.found || memcmp(info.txid, in->prev_txid, 32)) return P_ERR_UTXO;
        prevtx_off[idx] = (uint32_t)(uintptr_t)nwu->val; /* an offset into linear memory on wasm32 */
        prevtx_len[idx] = (uint32_t)nwu->vlen;
    }
    if (wu) {
        rd_t w = {wu->val, wu->vlen, 0, 0};
        uint64_t amount = rd_le(&w, 8);
        size_t len = (size_t)rd_varint(&w);
        const uint8_t *spk = rd_take(&w, len);
        plan_input_t prev = *in;
        if (w.err || w.pos != wu->vlen) return P_ERR_FORMAT;
        if (len > PLAN_MAX_SPK) return P_ERR_UNSUPPORTED;
        in->amount = amount;
        memset(&in->spk, 0, sizeof(in->spk));
        set_script(&in->spk, spk, len);
        if (nwu && (prev.amount != in->amount || memcmp(&prev.spk, &in->spk, sizeof(in->spk)))) return P_ERR_UTXO;
    }
    if (!wu && !nwu) return P_ERR_UTXO;
    if (sighash != 0xffffffffu && sighash > 0xff) return P_ERR_UNSUPPORTED;

    const cand_t *c = NULL;
    if (is_p2wpkh(&in->spk) && bip32.found && !signed_by_cand) {
        c = &bip32;
        in->sighash_type = sighash == 0xffffffffu ? 0x01 : (uint8_t)sighash;
    } else if (is_p2tr(&in->spk) && tap.found && !has_merkle && !has_tapsig) {
        c = &tap;
        in->sighash_type = sighash == 0xffffffffu ? 0x00 : (uint8_t)sighash;
    }
    if (c && !finalized) {
        in->key.depth = c->depth;
        in->key.fingerprint = fp;
        memcpy(in->key.path, c->path, sizeof(c->path));
    } else {
        in->sighash_type = 0;
    }
    return P_OK;
}

static int parse_output(rd_t *r, unsigned idx, uint32_t fp) {
    kv_t kv[MAX_KV];
    size_t n, end;
    plan_output_t *o = &plan.outputs[idx];
    cand_t bip32 = {0}, tap = {0};
    int has_tree = 0;
    int rc = read_map(r, kv, &n, &end);
    if (rc) return rc;
    for (size_t i = 0; i < n; i++) {
        const kv_t *e = &kv[i];
        switch (e->key[0]) {
        case 0x00: case 0x01: if (e->klen != 1) return P_ERR_FORMAT; break;
        case 0x02: {
            cand_t ignore = {0};
            if ((e->klen != 34 && e->klen != 66) || !keypath(e->val, e->vlen, fp, e->klen == 34 ? &bip32 : &ignore))
                return P_ERR_FORMAT;
            break;
        }
        case 0x03: case 0x04: return P_ERR_FORMAT; /* PSBT v2 only */
        case 0x05: if (e->klen != 1 || e->vlen != 32) return P_ERR_FORMAT; break;
        case 0x06: if (e->klen != 1 || e->vlen == 0) return P_ERR_FORMAT; has_tree = 1; break;
        case 0x07:
            if (e->klen != 33 || !tap_keypath(e->val, e->vlen, fp, &tap)) return P_ERR_FORMAT;
            break;
        default: break;
        }
    }
    const cand_t *c = is_p2wpkh(&o->spk) && bip32.found ? &bip32
                    : is_p2tr(&o->spk) && tap.found && !has_tree ? &tap : NULL;
    if (c) {
        o->key.depth = c->depth;
        o->key.fingerprint = fp;
        memcpy(o->key.path, c->path, sizeof(c->path));
    }
    return P_OK;
}

unsigned char *EXPORT(parser_input)(void) { return in_buf; }
unsigned EXPORT(parser_input_cap)(void) { return PSBT_MAX; }
plan_t *EXPORT(parser_plan)(void) { return &plan; }
plan_sig_t *EXPORT(parser_sigs)(void) { return sigs; }
unsigned char *EXPORT(parser_output)(void) { return out_buf; }
unsigned EXPORT(parser_prevtx_off)(unsigned i) { return i < PLAN_MAX_INPUTS ? prevtx_off[i] : 0; }
unsigned EXPORT(parser_prevtx_len)(unsigned i) { return i < PLAN_MAX_INPUTS ? prevtx_len[i] : 0; }

/* Called after the host writes len bytes to parser_input(). fp is the signer's master fingerprint (not a secret) */
int EXPORT(parser_parse)(unsigned len, unsigned fp) {
    static const uint8_t magic[5] = {'p', 's', 'b', 't', 0xff};
    rd_t r = {in_buf, len, 0, 0};
    int rc;

    parsed = 0;
    memset(&plan, 0, sizeof(plan));
    memset(prevtx_off, 0, sizeof(prevtx_off));
    memset(prevtx_len, 0, sizeof(prevtx_len));
    if (len > PSBT_MAX) return P_ERR_LIMIT;
    in_len = len;
    if (len < 5 || memcmp(rd_take(&r, 5), magic, 5)) return P_ERR_MAGIC;
    if ((rc = parse_global(&r))) return rc;
    for (unsigned i = 0; i < plan.n_inputs; i++)
        if ((rc = parse_input(&r, i, fp))) return rc;
    for (unsigned i = 0; i < plan.n_outputs; i++)
        if ((rc = parse_output(&r, i, fp))) return rc;
    if (r.pos != len) return P_ERR_FORMAT;
    plan.magic = PLAN_MAGIC;
    plan.version = PLAN_VERSION;
    parsed = 1;
    return P_OK;
}

/* Called after the host writes n signatures to parser_sigs(). Returns the signed PSBT length, or a negative value */
int EXPORT(parser_finalize)(unsigned n) {
    int by_input[PLAN_MAX_INPUTS];
    size_t o = 0, prev = 0;

    if (!parsed || n > PLAN_MAX_INPUTS) return -P_ERR_SIG;
    for (unsigned i = 0; i < PLAN_MAX_INPUTS; i++) by_input[i] = -1;
    for (unsigned k = 0; k < n; k++) {
        const plan_sig_t *s = &sigs[k];
        const plan_input_t *in;
        if (s->input >= plan.n_inputs || by_input[s->input] >= 0) return -P_ERR_SIG;
        in = &plan.inputs[s->input];
        if (in->key.depth == 0) return -P_ERR_SIG;
        if (is_p2wpkh(&in->spk) ? (s->pubkey[0] != 2 && s->pubkey[0] != 3) || s->sig_len < 9 || s->sig_len > 73
                                : s->pubkey[0] != 0 || (s->sig_len != 64 && s->sig_len != 65))
            return -P_ERR_SIG;
        by_input[s->input] = (int)k;
    }
    for (unsigned i = 0; i < plan.n_inputs; i++) {
        const plan_sig_t *s;
        if (by_input[i] < 0) continue;
        s = &sigs[by_input[i]];
        memcpy(out_buf + o, in_buf + prev, in_map_end[i] - prev);
        o += in_map_end[i] - prev;
        prev = in_map_end[i];
        /* every length is below 0xfd, so each compact size is one byte */
        if (is_p2wpkh(&plan.inputs[i].spk)) {
            out_buf[o++] = 34;
            out_buf[o++] = 0x02;
            memcpy(out_buf + o, s->pubkey, 33), o += 33;
        } else {
            out_buf[o++] = 1;
            out_buf[o++] = 0x13;
        }
        out_buf[o++] = s->sig_len;
        memcpy(out_buf + o, s->sig, s->sig_len), o += s->sig_len;
    }
    memcpy(out_buf + o, in_buf + prev, in_len - prev);
    o += in_len - prev;
    return (int)o;
}

/* ---- UR (animated QR) ---- */

static int ur_ready;

/* Starts a new UR. The reassembly buffer is out_buf, which is free until parser_finalize() */
void EXPORT(parser_ur_reset)(void) {
    ur_decoder_reset(out_buf, sizeof(out_buf));
    ur_ready = 1;
}

/* Called after the host writes one QR payload (len bytes) to parser_input(). Returns the PSBT length once the
 * UR is complete, with the PSBT now at the start of parser_input() for parser_parse(); 0 while more parts are
 * needed; a negative UR_ERR_* for a rejected part, which does not disturb the parts received so far */
int EXPORT(parser_ur_receive)(unsigned len) {
    const uint8_t *psbt;
    size_t psbt_len;
    long n;

    if (!ur_ready) parser_ur_reset();
    if (len > PSBT_MAX) return UR_ERR_LIMIT;
    if ((n = ur_decoder_receive((char *)in_buf, len)) <= 0) return (int)n;
    if ((strcmp(ur_decoder_type(), "crypto-psbt") && strcmp(ur_decoder_type(), "psbt")) ||
        !ur_cbor_bytes(ur_decoder_message(), (size_t)n, &psbt, &psbt_len))
        return UR_ERR_TYPE;
    if (psbt_len > PSBT_MAX) return UR_ERR_LIMIT;
    memmove(in_buf, psbt, psbt_len);
    return (int)psbt_len;
}

/* Parts expected (upper 16 bits; 0 until the first multipart part) and fragments recovered (lower 16 bits) */
unsigned EXPORT(parser_ur_progress)(void) {
    unsigned expected, received;
    ur_decoder_progress(&expected, &received);
    return expected << 16 | received;
}

/* Encodes the first len bytes of parser_output() (the signed PSBT from parser_finalize()) as a crypto-psbt UR
 * with fragments of at most max_fragment_len bytes. Returns the number of pure parts, or a negative UR_ERR_*.
 * Part text is written over parser_input(), so parse again before another parser_finalize() */
int EXPORT(parser_ur_encode_start)(unsigned len, unsigned max_fragment_len) {
    if (len > sizeof(out_buf)) return UR_ERR_LIMIT;
    parsed = 0;
    return (int)ur_encoder_start("crypto-psbt", out_buf, len, max_fragment_len);
}

/* Writes the next part to parser_input() and returns its length. Parts after the pure ones are mixed, so
 * showing them in a loop lets a scanner that missed some recover the message */
int EXPORT(parser_ur_encode_next)(void) {
    return (int)ur_encoder_next((char *)in_buf, sizeof(in_buf));
}
