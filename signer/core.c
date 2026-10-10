#include "core.h"
#include <string.h>
#include "wipe.h"
#include "bip32.h"
#include "bip85.h"
#include "hash.h"
#include "address.h"
#include "sighash.h"
#include "tx.h"
#include "cbor.h"
#include "multisig.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_preallocated.h"
#include "secp256k1_recovery.h"
#include "secp256k1_schnorrsig.h"

#define H 0x80000000u
#define MAX_MONEY 2100000000000000ull
#define MAX_ADDRESS_INDEX 100000 /* highest index we will call ours; anything beyond shows as external */

static uint8_t ctx_mem[256] __attribute__((aligned(16)));
static secp256k1_context *ctx;
static core_network_t network;
static bip32_node_t master;
static uint32_t master_fp;
static int seed_loaded;
static uint8_t reviewed_hash[32];
static int reviewed;
static uint8_t msg[CORE_MESSAGE_MAX], msg_hash[32]; /* the message review showed, and what binds it to sign */
static uint32_t msg_path[5];
static size_t msg_len;
static int msg_reviewed;
static ms_wallet_t wallet; /* the registered multisig, with ours its key that the seed re-derives */
static int wallet_ours = -1;

enum { SPK_OTHER, SPK_P2WPKH, SPK_P2SH_P2WPKH, SPK_P2TR, SPK_P2WSH };

static int spk_type(const plan_script_t *s) {
    if (s->len == 22 && s->bytes[0] == 0x00 && s->bytes[1] == 20) return SPK_P2WPKH;
    if (s->len == 23 && s->bytes[0] == 0xa9 && s->bytes[1] == 20 && s->bytes[22] == 0x87) return SPK_P2SH_P2WPKH;
    if (s->len == 34 && s->bytes[0] == 0x51 && s->bytes[1] == 32) return SPK_P2TR;
    if (s->len == 34 && s->bytes[0] == 0x00 && s->bytes[1] == 32) return SPK_P2WSH;
    return SPK_OTHER;
}

/* OP_m, n compressed keys, OP_n, OP_CHECKMULTISIG with 1 <= m <= n <= 3. Returns n, or 0 for any other script */
static unsigned multisig_keys(const plan_wscript_t *w) {
    unsigned n = w->len >= 3 ? (w->len - 3u) / 34u : 0, m = w->bytes[0] - 0x50u;
    if (n == 0 || w->len != 3 + 34 * n || m < 1 || m > n || w->bytes[w->len - 2] != 0x50 + n ||
        w->bytes[w->len - 1] != 0xae)
        return 0;
    for (unsigned i = 0; i < n; i++)
        if (w->bytes[1 + 34 * i] != 33 || (w->bytes[2 + 34 * i] != 2 && w->bytes[2 + 34 * i] != 3)) return 0;
    return n;
}

/* BIP86 tweak, no script tree: moves the secret key to the output key and returns the x-only form */
static int taproot_tweak(uint8_t seckey[32], uint8_t xonly_out[32], secp256k1_keypair *kp) {
    secp256k1_xonly_pubkey internal, output;
    uint8_t internal_ser[32], tweak[32];
    int ok = secp256k1_keypair_create(ctx, kp, seckey) && secp256k1_keypair_xonly_pub(ctx, &internal, NULL, kp) &&
             secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &internal) &&
             secp256k1_tagged_sha256(ctx, tweak, (const uint8_t *)"TapTweak", 8, internal_ser, 32) &&
             secp256k1_keypair_xonly_tweak_add(ctx, kp, tweak) && secp256k1_keypair_xonly_pub(ctx, &output, NULL, kp) &&
             secp256k1_xonly_pubkey_serialize(ctx, xonly_out, &output);
    wipe(tweak, sizeof(tweak));
    return ok;
}

/* Does the key at this derivation actually control spk? On a match the key is left in node */
/* A key's P2WPKH script, or with nested BIP49's P2SH of it, whose redeem script is 0014{HASH160(pubkey)}.
 * Returns the script's length */
static size_t wpkh_spk(const uint8_t pub[33], int nested, uint8_t spk[23]) {
    uint8_t redeem[22] = {0x00, 20};
    hash160(pub, 33, redeem + 2);
    if (!nested) return memcpy(spk, redeem, sizeof(redeem)), sizeof(redeem);
    spk[0] = 0xa9, spk[1] = 20, spk[22] = 0x87;
    hash160(redeem, sizeof(redeem), spk + 2);
    return 23;
}

static int owns(const plan_keypath_t *key, const plan_script_t *spk, const plan_wscript_t *ws, bip32_node_t *node) {
    uint8_t pub[33], mine[32], xonly[32];
    secp256k1_keypair kp;
    int type = spk_type(spk), ok = 0;

    if (key->fingerprint != master_fp || !bip32_derive(ctx, &master, key->path, key->depth, node)) return 0;
    if ((type == SPK_P2WPKH || type == SPK_P2SH_P2WPKH) && bip32_pubkey(ctx, node->key, pub)) {
        ok = wpkh_spk(pub, type == SPK_P2SH_P2WPKH, mine) == spk->len && !memcmp(mine, spk->bytes, spk->len);
    } else if (type == SPK_P2TR && taproot_tweak(node->key, xonly, &kp)) {
        ok = !memcmp(xonly, spk->bytes + 2, 32);
    } else if (type == SPK_P2WSH && ws && bip32_pubkey(ctx, node->key, pub)) {
        unsigned n = multisig_keys(ws);
        sha256(ws->bytes, ws->len, mine);
        ok = n && !memcmp(mine, spk->bytes + 2, 32);
        for (unsigned i = 0, found = 0; ok && i <= n; i++) {
            if (i == n) ok = found;
            else found |= !memcmp(ws->bytes + 2 + 34 * i, pub, 33);
        }
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
    for (unsigned i = 0; i < PLAN_MAX_INPUTS; i++) {
        const plan_wscript_t *w = &p->wscripts[i];
        if (w->len > PLAN_MAX_WSCRIPT) return 0;
        for (unsigned k = w->len; k < PLAN_MAX_WSCRIPT; k++)
            if (w->bytes[k]) return 0;
        if (w->len && (i >= p->n_inputs || spk_type(&p->inputs[i].spk) != SPK_P2WSH || !p->inputs[i].key.depth))
            return 0;
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

/* Is this key path ours in the registered wallet, and the witness script the one the wallet makes there? With
 * ws NULL, writes that script's P2WSH hash to spk_hash instead */
static int in_wallet_at(const plan_keypath_t *k, const plan_wscript_t *ws, uint8_t spk_hash[32]) {
    const ms_key_t *m = &wallet.keys[wallet_ours];
    plan_wscript_t mine;
    if (k->depth != m->depth + 2 || k->fingerprint != master_fp || memcmp(k->path, m->path, m->depth * 4u) ||
        k->path[m->depth] > 1 || k->path[m->depth + 1] >= MAX_ADDRESS_INDEX ||
        !ms_wscript(&wallet, k->path[m->depth], k->path[m->depth + 1], &mine))
        return 0;
    if (!ws) return sha256(mine.bytes, mine.len, spk_hash), 1;
    return mine.len == ws->len && !memcmp(mine.bytes, ws->bytes, ws->len);
}

static int in_wallet(const plan_keypath_t *k, const plan_wscript_t *ws) {
    return in_wallet_at(k, ws, NULL);
}

/* A P2WSH output is change only with a registered wallet, when we sign one of its inputs, and when the wallet's
 * keys at that path hash to the output's script */
static int wallet_owner(const plan_t *p, const core_review_t *r, const plan_output_t *o) {
    uint8_t h[32];
    if (wallet_ours < 0 || !in_wallet_at(&o->key, NULL, h) || memcmp(h, o->spk.bytes + 2, 32)) return CORE_OUT_EXTERNAL;
    for (unsigned i = 0; i < p->n_inputs; i++)
        if (r->will_sign[i] && spk_type(&p->inputs[i].spk) == SPK_P2WSH)
            return o->key.path[wallet.keys[wallet_ours].depth] ? CORE_OUT_CHANGE : CORE_OUT_SELF;
    return CORE_OUT_EXTERNAL;
}

/* An output counts as ours only on the receive (0) or change (1) chain of the same account as the
 * inputs we sign, and only when the re-derived key produces that exact script */
static int output_owner(const plan_t *p, const core_review_t *r, const plan_output_t *o) {
    const plan_keypath_t *k = &o->key;
    int type = spk_type(&o->spk);
    bip32_node_t node;
    uint32_t purpose = type == SPK_P2WPKH        ? (84 | H)
                       : type == SPK_P2SH_P2WPKH ? (49 | H)
                       : type == SPK_P2TR        ? (86 | H)
                                                 : 0;

    if (type == SPK_P2WSH) return wallet_owner(p, r, o);
    if (!purpose || k->depth != 5 || k->path[0] != purpose || k->path[1] != ((uint32_t)network | H) ||
        !(k->path[2] & H) || k->path[3] > 1 || k->path[4] >= MAX_ADDRESS_INDEX)
        return CORE_OUT_EXTERNAL;
    for (unsigned i = 0; i < p->n_inputs; i++) {
        const plan_keypath_t *ik = &p->inputs[i].key;
        if (r->will_sign[i] && ik->depth == 5 && !memcmp(ik->path, k->path, 3 * sizeof(uint32_t))) {
            int ok = owns(k, &o->spk, NULL, &node);
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
    reviewed = msg_reviewed = 0; /* an approval given under the other network is not this one's */
    core_multisig_unload();      /* and neither is a wallet of its keys */
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
    core_multisig_unload();
    wipe(&master, sizeof(master));
    master_fp = 0;
    seed_loaded = 0;
    reviewed = 0;
    msg_reviewed = 0;
    wipe(msg, sizeof(msg));
    wipe(msg_hash, sizeof(msg_hash));
    wipe(msg_path, sizeof(msg_path));
    msg_len = 0;
}

uint32_t core_fingerprint(void) {
    return master_fp;
}

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
        if (type == SPK_OTHER || (type == SPK_P2WSH && !multisig_keys(&p->wscripts[i]))) return CORE_ERR_SCRIPT;
        if (type != SPK_P2TR ? in->sighash_type != 0x01 : in->sighash_type > 0x01) return CORE_ERR_SIGHASH;
        if (!owns(&in->key, &in->spk, &p->wscripts[i], &node)) return CORE_ERR_NOT_OURS;
        wipe(&node, sizeof(node));
        if (type == SPK_P2WSH && wallet_ours >= 0 && !in_wallet(&in->key, &p->wscripts[i])) return CORE_ERR_WALLET;
        r->will_sign[i] = 1;
        r->n_sign++;
        has_v0 |= type != SPK_P2TR;
    }
    if (!r->n_sign) return CORE_ERR_NOTHING_TO_SIGN;

    /* BIP143 commits only to the amount of the input being signed, so with two or more inputs every
     * amount is checked against the previous transaction it claims to come from */
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

static int sign_input(const plan_t *p, unsigned i, core_sig_t *s) {
    const plan_input_t *in = &p->inputs[i];
    uint8_t digest[32], xonly[32];
    secp256k1_ecdsa_signature sig;
    secp256k1_keypair kp;
    secp256k1_pubkey pub;
    secp256k1_xonly_pubkey xpub;
    bip32_node_t node;
    size_t len = 72;
    int ok = owns(&in->key, &in->spk, &p->wscripts[i], &node);

    s->input = (uint8_t)i;
    if (ok && spk_type(&in->spk) != SPK_P2TR) {
        /* low-R grinding, as Bitcoin Core does it: retry with a counter as RFC6979 extra data until R < 0x80 */
        uint8_t extra[32] = {0}, compact[64], pkh[20];
        uint32_t counter = 0;
        ok = bip32_pubkey(ctx, node.key, s->pubkey);
        hash160(s->pubkey, 33, pkh);
        ok = ok && (spk_type(&in->spk) == SPK_P2WSH ? sighash_bip143_p2wsh(p, i, &p->wscripts[i], digest)
                                                    : sighash_bip143_p2wpkh(p, i, pkh, digest));
        do {
            ok = ok && secp256k1_ecdsa_sign(ctx, &sig, digest, node.key, NULL, counter ? extra : NULL) &&
                 secp256k1_ecdsa_signature_serialize_compact(ctx, compact, &sig);
            counter++;
            for (int k = 0; k < 4; k++) extra[k] = (uint8_t)(counter >> (8 * k));
        } while (ok && compact[0] >= 0x80);
        /* Verify before letting it out: collecting a glitched signature next to a good one can recover the key */
        ok = ok && secp256k1_ec_pubkey_create(ctx, &pub, node.key) && secp256k1_ecdsa_verify(ctx, &sig, digest, &pub) &&
             secp256k1_ecdsa_signature_serialize_der(ctx, s->sig, &len, &sig);
        s->sig[len] = 0x01;
        s->sig_len = (uint8_t)(len + 1);
    } else if (ok) {
        /* aux is zero. BIP340's security does not depend on its quality, and being deterministic means
         * the same PSBT always yields the same signature, which another implementation can reproduce.
         * Core, Trezor, Jade and BDK all do this. **Revisit before MuSig2 or FROST**: BIP340 says
         * deterministic nonces are unsafe there */
        ok = taproot_tweak(node.key, xonly, &kp) && sighash_bip341_keypath(ctx, p, i, in->sighash_type, digest) &&
             secp256k1_schnorrsig_sign32(ctx, s->sig, digest, &kp, NULL) &&
             secp256k1_xonly_pubkey_parse(ctx, &xpub, xonly) &&
             secp256k1_schnorrsig_verify(ctx, s->sig, digest, 32, &xpub);
        s->pubkey[0] = 0;
        memcpy(s->pubkey + 1, xonly, 32);
        s->sig_len = 64;
        if (in->sighash_type) s->sig[s->sig_len++] = in->sighash_type;
    }
    wipe(&node, sizeof(node));
    wipe(&kp, sizeof(kp));
    return ok;
}

int core_sign(const plan_t *p, core_rng_t rng, core_sig_t sigs[PLAN_MAX_INPUTS], unsigned *n_sigs) {
    uint8_t h[32], blind[32];

    *n_sigs = 0;
    sha256((const uint8_t *)p, sizeof(*p), h);
    if (!reviewed || memcmp(h, reviewed_hash, 32)) return CORE_ERR_NOT_REVIEWED;
    /* Vary the intermediate values of every computation that touches the key, so power traces cannot
     * be averaged over repeated runs. The quality of this randomness does not matter: a predictable
     * value costs nothing in security, it just stops helping */
    if (rng && rng(blind, 32) && !secp256k1_context_randomize(ctx, blind)) return CORE_ERR_CRYPTO;
    wipe(blind, sizeof(blind));
    /* The hash above already proved this is the plan review saw, so only inputs review confirmed get here */
    for (unsigned i = 0; i < p->n_inputs; i++) {
        const plan_input_t *in = &p->inputs[i];
        if (in->key.depth == 0 || in->key.fingerprint != master_fp) continue;
        if (!sign_input(p, i, &sigs[*n_sigs])) {
            wipe(sigs, sizeof(core_sig_t) * PLAN_MAX_INPUTS);
            *n_sigs = 0;
            return CORE_ERR_CRYPTO;
        }
        (*n_sigs)++;
    }
    reviewed = 0;
    return CORE_OK;
}

int core_find_address(const char *addr, size_t len, uint32_t account, uint32_t count) {
    static const char b58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const int testnet = network == CORE_TESTNET;
    char want[ADDRESS_MAX], got[ADDRESS_MAX];
    int upper = 0, lower = 0, other = 0, rc = -CORE_ERR_NOT_FOUND;
    unsigned purpose, need;
    uint32_t path[3];
    bip32_node_t acct, chain, child;
    secp256k1_keypair kp;
    uint8_t spk[34], pub[33], cpub[33];
    size_t n;

    if (!seed_loaded) return -CORE_ERR_NO_SEED;
    if (len < 4 || len >= ADDRESS_MAX || account >= H || !count || count > MAX_ADDRESS_INDEX) return -CORE_ERR_FORMAT;
    if (addr[0] == (testnet ? '2' : '3')) { /* BIP49's P2SH-P2WPKH, in base58, where case is part of the address */
        for (size_t i = 0; i < len; i++) other |= !addr[i] || !strchr(b58, addr[i]);
        memcpy(want, addr, len);
        purpose = 49, need = testnet ? 35 : 34;
    } else { /* BIP173 allows all upper case, which is what a QR's alphanumeric mode carries, but not mixed */
        for (size_t i = 0; i < len; i++) {
            char c = addr[i];
            upper |= c >= 'A' && c <= 'Z';
            lower |= c >= 'a' && c <= 'z';
            other |= !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z');
            want[i] = c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
        }
        if (memcmp(want, testnet ? "tb1" : "bc1", 3) || (want[3] != 'q' && want[3] != 'p')) other = 1;
        purpose = want[3] == 'q' ? 84 : 86, need = purpose == 84 ? 42 : 62;
    }
    want[len] = 0;
    if (other || (upper && lower)) return -CORE_ERR_FORMAT;
    if (len != need) return -CORE_ERR_NOT_FOUND; /* P2WSH, a P2SH of something else, or cut short: not ours */
    n = purpose == 49 ? 23 : purpose == 84 ? 22 : 34;

    /* The chain's public key once, not once a child: it is half the work of each unhardened step */
    path[0] = purpose | H, path[1] = (uint32_t)network | H, path[2] = account | H;
    if (!bip32_derive(ctx, &master, path, 3, &acct)) rc = -CORE_ERR_CRYPTO;
    for (uint32_t c = 0; rc == -CORE_ERR_NOT_FOUND && c < 2; c++) {
        if (!bip32_derive(ctx, &acct, &c, 1, &chain) || !bip32_pubkey(ctx, chain.key, cpub)) rc = -CORE_ERR_CRYPTO;
        for (uint32_t i = 0; rc == -CORE_ERR_NOT_FOUND && i < count; i++) {
            int ok = bip32_child(&chain, cpub, i, &child);
            if (ok && purpose != 86) {
                ok = bip32_pubkey(ctx, child.key, pub);
                wpkh_spk(pub, purpose == 49, spk);
            } else if (ok) {
                ok = taproot_tweak(child.key, spk + 2, &kp);
                spk[0] = 0x51, spk[1] = 32;
            }
            if (!ok) rc = -CORE_ERR_CRYPTO;
            else if (address_encode(spk, n, testnet, got) && !strcmp(got, want)) rc = (int)(c << 20 | i);
        }
    }
    wipe(&acct, sizeof(acct));
    wipe(&chain, sizeof(chain));
    wipe(&child, sizeof(child));
    wipe(&kp, sizeof(kp));
    return rc;
}

int core_bip85_mnemonic(unsigned words, uint32_t index, char *out, size_t cap) {
    return seed_loaded ? bip85_bip39(ctx, &master, words, index, out, cap) : 0;
}

static void msg_binding(uint8_t out[32]) {
    sha256_ctx h;
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)msg_path, sizeof(msg_path));
    sha256_update(&h, (const uint8_t *)&msg_len, sizeof(msg_len));
    sha256_update(&h, msg, msg_len);
    sha256_final(&h, out);
}

int core_message_review(const uint8_t *m, size_t len, unsigned purpose, uint32_t account, uint32_t chain,
                        uint32_t index, core_message_t *out) {
    bip32_node_t node;
    uint8_t pub[33], spk[23];
    int printable = 1, ok;

    msg_reviewed = 0;
    wipe(out, sizeof(*out));
    if (!seed_loaded) return CORE_ERR_NO_SEED;
    if (len > CORE_MESSAGE_MAX || (purpose != 49 && purpose != 84) || account >= H || chain > 1 ||
        index >= MAX_ADDRESS_INDEX)
        return CORE_ERR_FORMAT;
    msg_path[0] = purpose | H, msg_path[1] = (uint32_t)network | H, msg_path[2] = account | H;
    msg_path[3] = chain, msg_path[4] = index;
    ok = bip32_derive(ctx, &master, msg_path, 5, &node) && bip32_pubkey(ctx, node.key, pub);
    wipe(&node, sizeof(node));
    if (!ok) return CORE_ERR_CRYPTO;
    if (!address_encode(spk, wpkh_spk(pub, purpose == 49, spk), network == CORE_TESTNET, out->address))
        return CORE_ERR_CRYPTO;

    for (size_t i = 0; i < len; i++) printable &= m[i] >= 0x20 && m[i] <= 0x7e;
    out->text_kind = printable ? CORE_TEXT_MESSAGE : CORE_TEXT_HEX;
    if (printable) memcpy(out->text, m, len), out->text[len] = 0;
    else to_hex(m, len, out->text);

    memcpy(msg, m, len);
    msg_len = len;
    msg_binding(msg_hash);
    msg_reviewed = 1;
    return CORE_OK;
}

int core_message_sign(uint8_t sig[65]) {
    static const char prefix[] = "\x18"
                                 "Bitcoin Signed Message:\n";
    uint8_t now[32], hash[32], pub[33], got[33], n[3] = {(uint8_t)msg_len, 0, 0};
    size_t nlen = 1, glen = 33;
    bip32_node_t node;
    secp256k1_ecdsa_recoverable_signature rs;
    secp256k1_pubkey rec;
    sha256_ctx h;
    int recid = 0, ok;

    if (!msg_reviewed) return CORE_ERR_NOT_REVIEWED;
    msg_binding(now);
    msg_reviewed = 0;
    if (memcmp(now, msg_hash, 32)) return CORE_ERR_NOT_REVIEWED;
    if (msg_len >= 0xfd) n[0] = 0xfd, n[1] = (uint8_t)msg_len, n[2] = (uint8_t)(msg_len >> 8), nlen = 3;
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)prefix, sizeof(prefix) - 1);
    sha256_update(&h, n, nlen);
    sha256_update(&h, msg, msg_len);
    sha256d_final(&h, hash);

    /* RFC6979 with no extra data, as Core's signmessage does, so the same key gives Core's r and s. The
     * key it recovers to is checked before the signature leaves, as for a transaction */
    ok = bip32_derive(ctx, &master, msg_path, 5, &node) && bip32_pubkey(ctx, node.key, pub) &&
         secp256k1_ecdsa_sign_recoverable(ctx, &rs, hash, node.key, NULL, NULL) &&
         secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig + 1, &recid, &rs) &&
         secp256k1_ecdsa_recover(ctx, &rec, &rs, hash) &&
         secp256k1_ec_pubkey_serialize(ctx, got, &glen, &rec, SECP256K1_EC_COMPRESSED) && !memcmp(got, pub, 33);
    sig[0] = (uint8_t)((msg_path[0] == (84 | H) ? 39 : 35) + recid);
    wipe(&node, sizeof(node));
    wipe(&h, sizeof(h));
    if (!ok) wipe(sig, 65);
    return ok ? CORE_OK : CORE_ERR_CRYPTO;
}

/* m/purpose'/coin'/account' (BIP48 adds 2' for P2WSH) serialized as an xpub, with its path */
static int account_key(unsigned purpose, uint32_t account, uint32_t path[4], unsigned *depth, uint8_t ser[78]) {
    const uint32_t coin = network == CORE_TESTNET ? 1u : 0u;
    const uint32_t ver = network == CORE_TESTNET ? 0x043587cfu : 0x0488b21eu;
    bip32_node_t parent, node;
    uint8_t pub[33], h[20];
    unsigned o = 0;
    int ok;

    *depth = purpose == 48 ? 4 : 3;
    path[0] = purpose | H, path[1] = coin | H, path[2] = account | H, path[3] = 2 | H;
    /* Derived in two steps because the serialization needs the parent's fingerprint */
    ok = bip32_derive(ctx, &master, path, *depth - 1, &parent) && bip32_pubkey(ctx, parent.key, pub);
    hash160(pub, sizeof(pub), h);
    ok = ok && bip32_derive(ctx, &parent, path + *depth - 1, 1, &node) && bip32_pubkey(ctx, node.key, pub);
    /* version(4) depth(1) parent fingerprint(4) child number(4) chain code(32) pubkey(33) */
    for (int i = 3; i >= 0; i--) ser[o++] = (uint8_t)(ver >> (8 * i));
    ser[o++] = (uint8_t)*depth;
    memcpy(ser + o, h, 4), o += 4;
    for (int i = 3; i >= 0; i--) ser[o++] = (uint8_t)(path[*depth - 1] >> (8 * i));
    memcpy(ser + o, node.chain, 32), o += 32;
    memcpy(ser + o, pub, 33);
    wipe(&parent, sizeof(parent));
    wipe(&node, sizeof(node));
    return ok;
}

/* The account xpub (m/purpose'/coin'/account') and an output descriptor built from it. Hand these to
 * the PC and it can watch the wallet without ever holding a key */
int core_account_xpub(unsigned purpose, uint32_t account, char out[CORE_XPUB_MAX], char desc[CORE_DESC_MAX]) {
    const uint32_t coin = network == CORE_TESTNET ? 1u : 0u;
    uint32_t path[4];
    unsigned depth;
    uint8_t ser[78];
    char fp[9], acct[11];

    if (!master_fp) return CORE_ERR_NO_SEED;
    if ((purpose != 48 && purpose != 49 && purpose != 84 && purpose != 86) || account >= H) return CORE_ERR_FORMAT;
    if (!account_key(purpose, account, path, &depth, ser)) return CORE_ERR_CRYPTO;
    base58check_data(ser, sizeof(ser), out);

    for (int i = 0; i < 8; i++) fp[i] = "0123456789abcdef"[master_fp >> (28 - 4 * i) & 15];
    fp[8] = 0;
    {
        unsigned n = 0;
        char rev[10];
        uint32_t a = account;
        do rev[n++] = (char)('0' + a % 10), a /= 10;
        while (a);
        for (unsigned i = 0; i < n; i++) acct[i] = rev[n - 1 - i];
        acct[n] = 0;
    }
    /* An output descriptor Sparrow and others read as is; <0;1> covers receive and change in one line. For BIP48
     * it is the key expression that goes into sortedmulti(). Built by hand: snprintf drags stdio into the wasm */
    {
        const char *parts[] = {purpose == 86   ? "tr(["
                               : purpose == 49 ? "sh(wpkh(["
                               : purpose == 48 ? "["
                                               : "wpkh([",
                               fp,
                               purpose == 86   ? "/86h/"
                               : purpose == 49 ? "/49h/"
                               : purpose == 48 ? "/48h/"
                                               : "/84h/",
                               coin ? "1" : "0",
                               "h/",
                               acct,
                               purpose == 48 ? "h/2h]" : "h]",
                               out,
                               purpose == 49   ? "/<0;1>/*))"
                               : purpose == 48 ? "/<0;1>/*"
                                               : "/<0;1>/*)"};
        size_t o = 0;
        for (unsigned k = 0; k < sizeof(parts) / sizeof(*parts); k++) {
            size_t n = strlen(parts[k]);
            if (o + n + 1 > CORE_DESC_MAX) return CORE_ERR_CRYPTO;
            memcpy(desc + o, parts[k], n);
            o += n;
        }
        desc[o] = 0;
    }
    return CORE_OK;
}

int core_multisig_load(const char *text, size_t len, core_multisig_t *out) {
    char stated[ADDRESS_MAX];
    uint8_t pub[33], spk[34] = {0x00, 32};
    plan_wscript_t ws;
    bip32_node_t node;
    int ours = -1, rc = CORE_ERR_WALLET;

    core_multisig_unload();
    wipe(out, sizeof(*out));
    if (!seed_loaded) return CORE_ERR_NO_SEED;
    if (!ms_parse(text, len, network == CORE_TESTNET, &wallet, stated)) return CORE_ERR_FORMAT;
    /* Ours is the one key the seed re-derives at its origin, chain code and all. A fingerprint that matches with
     * another key is most likely the wrong passphrase */
    for (unsigned i = 0; i < wallet.n; i++) {
        const ms_key_t *k = &wallet.keys[i];
        if (k->fingerprint != master_fp) continue;
        if (ours >= 0 || !bip32_derive(ctx, &master, k->path, k->depth, &node) || !bip32_pubkey(ctx, node.key, pub) ||
            memcmp(pub, k->ser + 45, 33) || memcmp(node.chain, k->ser + 13, 32))
            goto done;
        ours = (int)i;
    }
    if (ours < 0 || !ms_wscript(&wallet, 0, 0, &ws)) goto done;
    sha256(ws.bytes, ws.len, spk + 2);
    if (!address_encode(spk, sizeof(spk), network == CORE_TESTNET, out->receive)) goto done;
    if (stated[0] && strcmp(stated, out->receive)) goto done; /* the coordinator derived some other wallet */
    if (!ms_descriptor(&wallet, network == CORE_TESTNET, out->descriptor)) goto done;
    out->threshold = wallet.threshold, out->n = wallet.n, out->ours = (uint8_t)ours;
    for (unsigned i = 0; i < wallet.n; i++) out->fingerprints[i] = wallet.keys[i].fingerprint;
    wallet_ours = ours;
    rc = CORE_OK;
done:
    wipe(&node, sizeof(node));
    if (rc) core_multisig_unload(), wipe(out, sizeof(*out));
    return rc;
}

void core_multisig_unload(void) {
    wipe(&wallet, sizeof(wallet));
    wallet_ours = -1;
}

/* crypto-account: the master fingerprint and, for the account, sh(wpkh()), wpkh(), tr() and the BIP48 key as
 * wsh(cosigner()), each tagged crypto-output (308) */
int core_account_cbor(uint32_t account, uint8_t *out, size_t cap) {
    static const unsigned purposes[] = {49, 84, 86, 48};
    static const unsigned tags[][2] = {{400, 404}, {404, 0}, {409, 0}, {401, 410}};
    cbor_t c = {out, 0, cap};
    uint32_t path[4];
    unsigned depth;
    uint8_t ser[78];

    if (!seed_loaded) return -CORE_ERR_NO_SEED;
    if (account >= H) return -CORE_ERR_FORMAT;
    cbor_head(&c, CBOR_MAP, 2);
    cbor_head(&c, CBOR_UINT, 1), cbor_head(&c, CBOR_UINT, master_fp);
    cbor_head(&c, CBOR_UINT, 2), cbor_head(&c, CBOR_ARRAY, 4);
    for (unsigned i = 0; i < 4; i++) {
        if (!account_key(purposes[i], account, path, &depth, ser)) return -CORE_ERR_CRYPTO;
        cbor_head(&c, CBOR_TAG, 308);
        for (unsigned t = 0; t < 2 && tags[i][t]; t++) cbor_head(&c, CBOR_TAG, tags[i][t]);
        cbor_hdkey(&c, ser, master_fp, path, depth, network == CORE_TESTNET);
    }
    return c.n > cap ? -CORE_ERR_FORMAT : (int)c.n;
}

/* crypto-output for the registered wallet: wsh(sortedmulti()), the keys in the order the coordinator gave */
int core_multisig_cbor(uint8_t *out, size_t cap) {
    cbor_t c = {out, 0, cap};
    if (wallet_ours < 0) return -CORE_ERR_WALLET;
    cbor_head(&c, CBOR_TAG, 401), cbor_head(&c, CBOR_TAG, 407);
    cbor_head(&c, CBOR_MAP, 2);
    cbor_head(&c, CBOR_UINT, 1), cbor_head(&c, CBOR_UINT, wallet.threshold);
    cbor_head(&c, CBOR_UINT, 2), cbor_head(&c, CBOR_ARRAY, wallet.n);
    for (unsigned i = 0; i < wallet.n; i++) {
        const ms_key_t *k = &wallet.keys[i];
        cbor_hdkey(&c, k->ser, k->fingerprint, k->path, k->depth, network == CORE_TESTNET);
    }
    return c.n > cap ? -CORE_ERR_FORMAT : (int)c.n;
}
