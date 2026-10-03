#include "core.h"
#include <string.h>
#include <stdio.h>
#include "wipe.h"
#include "bip32.h"
#include "hash.h"
#include "address.h"
#include "sighash.h"
#include "tx.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_preallocated.h"
#include "secp256k1_schnorrsig.h"

#define H 0x80000000u
#define MAX_MONEY 2100000000000000ull
#define MAX_ADDRESS_INDEX 100000 /* 自分のアドレスと認める index の上限。外れた値は外部出力として表示する */

static uint8_t ctx_mem[256] __attribute__((aligned(16)));
static secp256k1_context *ctx;
static core_network_t network;
static bip32_node_t master;
static uint32_t master_fp;
static int seed_loaded;
static uint8_t reviewed_hash[32];
static int reviewed;

enum { SPK_OTHER, SPK_P2WPKH, SPK_P2TR };

static int spk_type(const plan_script_t *s) {
    if (s->len == 22 && s->bytes[0] == 0x00 && s->bytes[1] == 20) return SPK_P2WPKH;
    if (s->len == 34 && s->bytes[0] == 0x51 && s->bytes[1] == 32) return SPK_P2TR;
    return SPK_OTHER;
}

/* BIP86: スクリプトツリー無しの tweak。seckey を出力鍵側に変換し、x-only 出力鍵を返す */
static int taproot_tweak(uint8_t seckey[32], uint8_t xonly_out[32], secp256k1_keypair *kp) {
    secp256k1_xonly_pubkey internal, output;
    uint8_t internal_ser[32], tweak[32];
    int ok = secp256k1_keypair_create(ctx, kp, seckey)
          && secp256k1_keypair_xonly_pub(ctx, &internal, NULL, kp)
          && secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &internal)
          && secp256k1_tagged_sha256(ctx, tweak, (const uint8_t *)"TapTweak", 8, internal_ser, 32)
          && secp256k1_keypair_xonly_tweak_add(ctx, kp, tweak)
          && secp256k1_keypair_xonly_pub(ctx, &output, NULL, kp)
          && secp256k1_xonly_pubkey_serialize(ctx, xonly_out, &output);
    wipe(tweak, sizeof(tweak));
    return ok;
}

/* key のパスで導出した鍵が spk を支配しているか。一致すれば node に鍵を残す */
static int owns(const plan_keypath_t *key, const plan_script_t *spk, bip32_node_t *node) {
    uint8_t pub[33], h[20], xonly[32];
    secp256k1_keypair kp;
    int type = spk_type(spk), ok = 0;

    if (key->fingerprint != master_fp || !bip32_derive(ctx, &master, key->path, key->depth, node)) return 0;
    if (type == SPK_P2WPKH && bip32_pubkey(ctx, node->key, pub)) {
        hash160(pub, 33, h);
        ok = !memcmp(h, spk->bytes + 2, 20);
    } else if (type == SPK_P2TR && taproot_tweak(node->key, xonly, &kp)) {
        ok = !memcmp(xonly, spk->bytes + 2, 32);
    }
    wipe(&kp, sizeof(kp));
    if (!ok) wipe(node, sizeof(*node));
    return ok;
}

static int script_ok(const plan_script_t *s) {
    if (s->len > PLAN_MAX_SPK) return 0;
    for (unsigned i = s->len; i < PLAN_MAX_SPK; i++)
        if (s->bytes[i]) return 0;
    return 1;
}

static int keypath_ok(const plan_keypath_t *k) {
    if (k->depth > PLAN_MAX_DEPTH || (k->depth == 0 && k->fingerprint)) return 0;
    for (unsigned i = k->depth; i < PLAN_MAX_DEPTH; i++)
        if (k->path[i]) return 0;
    return 1;
}

static int format_ok(const plan_t *p) {
    if (p->magic != PLAN_MAGIC || p->version != PLAN_VERSION) return 0;
    if (p->n_inputs == 0 || p->n_inputs > PLAN_MAX_INPUTS || p->n_outputs == 0 || p->n_outputs > PLAN_MAX_OUTPUTS)
        return 0;
    for (unsigned i = 0; i < PLAN_MAX_INPUTS; i++) {
        const plan_input_t *in = &p->inputs[i];
        if (i >= p->n_inputs) {
            static const plan_input_t zero;
            if (memcmp(in, &zero, sizeof(zero))) return 0;
            continue;
        }
        if (in->amount > MAX_MONEY || !script_ok(&in->spk) || !keypath_ok(&in->key)) return 0;
        if (in->key.depth == 0 && in->sighash_type) return 0;
    }
    for (unsigned i = 0; i < PLAN_MAX_OUTPUTS; i++) {
        const plan_output_t *o = &p->outputs[i];
        if (i >= p->n_outputs) {
            static const plan_output_t zero;
            if (memcmp(o, &zero, sizeof(zero))) return 0;
            continue;
        }
        if (o->amount > MAX_MONEY || !script_ok(&o->spk) || !keypath_ok(&o->key)) return 0;
    }
    return 1;
}

typedef struct {
    uint32_t vout;
    int found;
    uint64_t amount;
    const plan_script_t *spk;
} prevout_match_t;

static int on_prev_output(void *c, uint32_t index, uint64_t amount, const uint8_t *spk, size_t spk_len) {
    prevout_match_t *m = c;
    if (index == m->vout)
        m->found = amount == m->amount && spk_len == m->spk->len && !memcmp(spk, m->spk->bytes, spk_len);
    return 1;
}

static int prevtx_ok(const plan_input_t *in, const core_prevtx_t *prev) {
    prevout_match_t m = {in->prev_vout, 0, in->amount, &in->spk};
    tx_visitor_t v = {NULL, on_prev_output, &m};
    tx_info_t info;
    return tx_parse(prev->raw, prev->len, &v, &info) && m.found && !memcmp(info.txid, in->prev_txid, 32);
}

/* 自分の出力と認めるのは、署名する入力と同じアカウント配下の受取（0）/ お釣り（1）チェーンで、スクリプトが一致するものだけ */
static int output_owner(const plan_t *p, const core_review_t *r, const plan_output_t *o) {
    const plan_keypath_t *k = &o->key;
    int type = spk_type(&o->spk);
    bip32_node_t node;
    uint32_t purpose = type == SPK_P2WPKH ? (84 | H) : type == SPK_P2TR ? (86 | H) : 0;

    if (!purpose || k->depth != 5 || k->path[0] != purpose || k->path[1] != ((uint32_t)network | H)
        || !(k->path[2] & H) || k->path[3] > 1 || k->path[4] >= MAX_ADDRESS_INDEX)
        return CORE_OUT_EXTERNAL;
    for (unsigned i = 0; i < p->n_inputs; i++) {
        const plan_keypath_t *ik = &p->inputs[i].key;
        if (r->will_sign[i] && ik->depth == 5 && !memcmp(ik->path, k->path, 3 * sizeof(uint32_t))) {
            int ok = owns(k, &o->spk, &node);
            wipe(&node, sizeof(node));
            return !ok ? CORE_OUT_EXTERNAL : k->path[3] ? CORE_OUT_CHANGE : CORE_OUT_SELF;
        }
    }
    return CORE_OUT_EXTERNAL;
}

int core_init(core_network_t net) {
    if (secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) > sizeof(ctx_mem)) return 0;
    ctx = secp256k1_context_preallocated_create(ctx_mem, SECP256K1_CONTEXT_NONE);
    network = net;
    return ctx != NULL;
}

int core_load_seed(const uint8_t seed[64]) {
    uint8_t pub[33], h[20];
    core_unload();
    if (!bip32_master(seed, &master) || !bip32_pubkey(ctx, master.key, pub)) {
        core_unload();
        return 0;
    }
    hash160(pub, 33, h);
    master_fp = (uint32_t)h[0] << 24 | (uint32_t)h[1] << 16 | (uint32_t)h[2] << 8 | h[3];
    seed_loaded = 1;
    return 1;
}

void core_unload(void) {
    wipe(&master, sizeof(master));
    master_fp = 0;
    seed_loaded = 0;
    reviewed = 0;
}

uint32_t core_fingerprint(void) { return master_fp; }

int core_review(const plan_t *p, const core_prevtx_t prev[PLAN_MAX_INPUTS], core_review_t *r) {
    bip32_node_t node;
    int has_v0 = 0;

    reviewed = 0;
    wipe(r, sizeof(*r));
    if (!seed_loaded) return CORE_ERR_NO_SEED;
    if (!format_ok(p)) return CORE_ERR_FORMAT;

    for (unsigned i = 0; i < p->n_inputs; i++) {
        const plan_input_t *in = &p->inputs[i];
        int type = spk_type(&in->spk);
        r->total_in += in->amount;
        if (r->total_in > MAX_MONEY) return CORE_ERR_FORMAT;
        if (in->key.depth == 0 || in->key.fingerprint != master_fp) continue;
        if (type == SPK_OTHER) return CORE_ERR_SCRIPT;
        if (type == SPK_P2WPKH ? in->sighash_type != 0x01 : in->sighash_type > 0x01) return CORE_ERR_SIGHASH;
        if (!owns(&in->key, &in->spk, &node)) return CORE_ERR_NOT_OURS;
        wipe(&node, sizeof(node));
        r->will_sign[i] = 1;
        r->n_sign++;
        has_v0 |= type == SPK_P2WPKH;
    }
    if (!r->n_sign) return CORE_ERR_NOTHING_TO_SIGN;

    /* BIP143 は署名する入力の額にしかコミットしないので、2 入力以上なら全入力の額を元の取引で確かめる */
    for (unsigned i = 0; i < p->n_inputs; i++) {
        const core_prevtx_t *pv = prev ? &prev[i] : NULL;
        if (pv && pv->raw) {
            if (!prevtx_ok(&p->inputs[i], pv)) return CORE_ERR_PREVTX_MISMATCH;
        } else if (has_v0 && p->n_inputs > 1) {
            return CORE_ERR_PREVTX_MISSING;
        }
    }

    for (unsigned i = 0; i < p->n_outputs; i++) {
        r->total_out += p->outputs[i].amount;
        if (r->total_out > MAX_MONEY) return CORE_ERR_FORMAT;
        r->owner[i] = (uint8_t)output_owner(p, r, &p->outputs[i]);
    }
    if (r->total_out > r->total_in) return CORE_ERR_FEE;
    r->fee = r->total_in - r->total_out;

    sha256((const uint8_t *)p, sizeof(*p), reviewed_hash);
    reviewed = 1;
    return CORE_OK;
}

static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) out[2 * i] = hx[b[i] >> 4], out[2 * i + 1] = hx[b[i] & 15];
    out[2 * n] = 0;
}

void core_format_btc(uint64_t sats, char out[21]) {
    char t[21];
    int n = 0, o = 0;
    for (uint64_t v = sats; n < 9 || v; v /= 10) t[n++] = (char)('0' + v % 10);
    while (n) {
        out[o++] = t[--n];
        if (n == 8) out[o++] = '.';
    }
    out[o] = 0;
}

int core_display(const plan_t *p, const core_review_t *r, core_display_t *d) {
    uint8_t h[32];
    sha256((const uint8_t *)p, sizeof(*p), h);
    memset(d, 0, sizeof(*d));
    if (!reviewed || memcmp(h, reviewed_hash, 32)) return CORE_ERR_NOT_REVIEWED;
    d->fee = r->fee;
    d->n_outputs = p->n_outputs;
    for (unsigned i = 0; i < p->n_outputs; i++) {
        const plan_script_t *s = &p->outputs[i].spk;
        core_display_output_t *o = &d->outputs[i];
        o->amount = p->outputs[i].amount;
        o->owner = r->owner[i];
        if (o->owner == CORE_OUT_EXTERNAL) d->spend += o->amount;
        if (address_encode(s->bytes, s->len, network == CORE_TESTNET, o->text)) {
            o->text_kind = CORE_TEXT_ADDRESS;
        } else if (s->len && s->bytes[0] == 0x6a) {
            o->text_kind = CORE_TEXT_OP_RETURN;
            to_hex(s->bytes + 1, s->len - 1u, o->text);
        } else {
            o->text_kind = CORE_TEXT_SCRIPT;
            to_hex(s->bytes, s->len, o->text);
        }
    }
    return CORE_OK;
}

static int sign_input(const plan_t *p, unsigned i, core_rng_t rng, core_sig_t *s) {
    const plan_input_t *in = &p->inputs[i];
    uint8_t digest[32], aux[32], xonly[32];
    secp256k1_ecdsa_signature sig;
    secp256k1_keypair kp;
    bip32_node_t node;
    size_t len = 72;
    int ok = owns(&in->key, &in->spk, &node);

    s->input = (uint8_t)i;
    if (ok && spk_type(&in->spk) == SPK_P2WPKH) {
        /* Bitcoin Core と同じ low-R grinding: R が 0x80 未満になるまで counter を RFC6979 の追加データにして引き直す */
        uint8_t extra[32] = {0}, compact[64];
        uint32_t counter = 0;
        ok = sighash_bip143_p2wpkh(p, i, digest);
        do {
            ok = ok && secp256k1_ecdsa_sign(ctx, &sig, digest, node.key, NULL, counter ? extra : NULL)
                    && secp256k1_ecdsa_signature_serialize_compact(ctx, compact, &sig);
            counter++;
            for (int k = 0; k < 4; k++) extra[k] = (uint8_t)(counter >> (8 * k));
        } while (ok && compact[0] >= 0x80);
        ok = ok && secp256k1_ecdsa_signature_serialize_der(ctx, s->sig, &len, &sig)
          && bip32_pubkey(ctx, node.key, s->pubkey);
        s->sig[len] = 0x01;
        s->sig_len = (uint8_t)(len + 1);
    } else if (ok) {
        ok = rng(aux, 32) && taproot_tweak(node.key, xonly, &kp)
          && sighash_bip341_keypath(ctx, p, i, in->sighash_type, digest)
          && secp256k1_schnorrsig_sign32(ctx, s->sig, digest, &kp, aux);
        s->pubkey[0] = 0;
        memcpy(s->pubkey + 1, xonly, 32);
        s->sig_len = 64;
        if (in->sighash_type) s->sig[s->sig_len++] = in->sighash_type;
    }
    wipe(&node, sizeof(node));
    wipe(&kp, sizeof(kp));
    wipe(aux, sizeof(aux));
    return ok;
}

int core_sign(const plan_t *p, core_rng_t rng, core_sig_t sigs[PLAN_MAX_INPUTS], unsigned *n_sigs) {
    uint8_t h[32];

    *n_sigs = 0;
    sha256((const uint8_t *)p, sizeof(*p), h);
    if (!reviewed || memcmp(h, reviewed_hash, 32)) return CORE_ERR_NOT_REVIEWED;
    /* review と同じ plan であることはハッシュで保証済み。review が所有を確かめた入力だけがここを通る */
    for (unsigned i = 0; i < p->n_inputs; i++) {
        const plan_input_t *in = &p->inputs[i];
        if (in->key.depth == 0 || in->key.fingerprint != master_fp) continue;
        if (!sign_input(p, i, rng, &sigs[*n_sigs])) {
            wipe(sigs, sizeof(core_sig_t) * PLAN_MAX_INPUTS);
            *n_sigs = 0;
            return CORE_ERR_CRYPTO;
        }
        (*n_sigs)++;
    }
    reviewed = 0;
    return CORE_OK;
}

/* 口座の拡張公開鍵（m/84'/coin'/0'）と、それを使う出力ディスクリプタを作る。
 * これを PC 側へ渡せば、PC は鍵を知らないままウォッチオンリーで使える */
int core_account_xpub(char out[CORE_XPUB_MAX], char desc[CORE_DESC_MAX]) {
    const uint32_t coin = network == CORE_TESTNET ? 1u : 0u;
    uint32_t path[3] = {84u | H, coin | H, 0u | H};
    bip32_node_t parent, node;
    uint8_t pub[33], h[20], ser[78];
    char fp[9];
    int ok = 0;

    if (!master_fp) return 0;
    /* 親（m/84'/coin'）の指紋が要るので 2 段で導出する */
    if (!bip32_derive(ctx, &master, path, 2, &parent) || !bip32_pubkey(ctx, parent.key, pub)) goto done;
    hash160(pub, sizeof(pub), h);
    if (!bip32_derive(ctx, &parent, path + 2, 1, &node) || !bip32_pubkey(ctx, node.key, pub)) goto done;

    /* version(4) depth(1) 親の指紋(4) 子番号(4) chain code(32) 公開鍵(33) */
    {
        const uint32_t ver = network == CORE_TESTNET ? 0x043587cfu : 0x0488b21eu;
        unsigned o = 0;
        for (int i = 3; i >= 0; i--) ser[o++] = (uint8_t)(ver >> (8 * i));
        ser[o++] = 3;
        memcpy(ser + o, h, 4), o += 4;
        for (int i = 3; i >= 0; i--) ser[o++] = (uint8_t)(path[2] >> (8 * i));
        memcpy(ser + o, node.chain, 32), o += 32;
        memcpy(ser + o, pub, 33);
    }
    base58check_data(ser, sizeof(ser), out);

    for (int i = 0; i < 8; i++) fp[i] = "0123456789abcdef"[master_fp >> (28 - 4 * i) & 15];
    fp[8] = 0;
    /* Sparrow などがそのまま読める出力ディスクリプタ。受取と釣りの両方を 1 行で表す */
    if ((size_t)snprintf(desc, CORE_DESC_MAX, "wpkh([%s/84h/%luh/0h]%s/<0;1>/*)", fp, (unsigned long)coin, out) >= CORE_DESC_MAX)
        goto done;
    ok = 1;
done:
    wipe(&parent, sizeof(parent));
    wipe(&node, sizeof(node));
    return ok;
}
