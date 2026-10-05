#include <stdio.h>
#include <string.h>
#include "core.h"
#include "address.h"
#include "hash.h"
#include "sighash.h"
#include "tx.h"
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
#include "core_vectors.h"

#define H 0x80000000u

static int failures, checks;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; printf("FAIL %s:%d ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void unhex(const char *s, uint8_t *out) {
    for (size_t i = 0; s[2 * i]; i++) sscanf(s + 2 * i, "%2hhx", &out[i]);
}

static int zero_rng(uint8_t *buf, size_t len) { memset(buf, 0, len); return 1; }

/* Build a plan from a raw transaction, taking scripts and amounts from the utxo side. Stands in for
 * parser.wasm so that core can be tested on its own */
typedef struct { plan_t *p; } build_t;
static int b_in(void *c, uint32_t i, const uint8_t prevout[36], size_t script_sig_len, uint32_t seq) {
    (void)script_sig_len;
    plan_t *p = ((build_t *)c)->p;
    if (i >= PLAN_MAX_INPUTS) return 0;
    memcpy(p->inputs[i].prev_txid, prevout, 32);
    p->inputs[i].prev_vout = prevout[32] | (uint32_t)prevout[33] << 8 | (uint32_t)prevout[34] << 16 | (uint32_t)prevout[35] << 24;
    p->inputs[i].sequence = seq;
    return 1;
}
static int b_out(void *c, uint32_t i, uint64_t amount, const uint8_t *spk, size_t len) {
    plan_t *p = ((build_t *)c)->p;
    if (i >= PLAN_MAX_OUTPUTS || len > PLAN_MAX_SPK) return 0;
    p->outputs[i].amount = amount;
    p->outputs[i].spk.len = (uint8_t)len;
    memcpy(p->outputs[i].spk.bytes, spk, len);
    return 1;
}
static int plan_from_tx(const uint8_t *raw, size_t len, plan_t *p) {
    build_t b = {p};
    tx_visitor_t v = {b_in, b_out, &b};
    tx_info_t info;
    memset(p, 0, sizeof(*p));
    if (!tx_parse(raw, len, &v, &info)) return 0;
    p->magic = PLAN_MAGIC, p->version = PLAN_VERSION;
    p->tx_version = info.version, p->locktime = info.locktime;
    p->n_inputs = (uint8_t)info.n_inputs, p->n_outputs = (uint8_t)info.n_outputs;
    return 1;
}

static void set_spk(plan_script_t *s, const uint8_t *b, size_t n) {
    memset(s, 0, sizeof(*s));
    s->len = (uint8_t)n;
    memcpy(s->bytes, b, n);
}

static void set_key(plan_keypath_t *k, uint32_t p0, uint32_t p1, uint32_t p2, uint32_t p3, uint32_t p4) {
    memset(k, 0, sizeof(*k));
    k->depth = 5, k->fingerprint = TV_FP;
    k->path[0] = p0, k->path[1] = p1, k->path[2] = p2, k->path[3] = p3, k->path[4] = p4;
}

static void test_bip143(void) {
    static const char *tx = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
    uint8_t raw[256], spk[22], want[32], key[32], digest[32], der[80], want_sig[80];
    size_t n = strlen(tx) / 2, len = sizeof(der);
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_ecdsa_signature sig;
    plan_t p;

    unhex(tx, raw);
    CHECK(plan_from_tx(raw, n, &p), "bip143 parse");
    unhex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1", spk);
    set_spk(&p.inputs[1].spk, spk, 22);
    p.inputs[1].amount = 600000000;
    unhex("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670", want);
    CHECK(sighash_bip143_p2wpkh(&p, 1, digest) && !memcmp(digest, want, 32), "bip143 sighash");
    unhex("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9", key);
    unhex("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee", want_sig);
    CHECK(secp256k1_ecdsa_sign(ctx, &sig, digest, key, NULL, NULL)
          && secp256k1_ecdsa_signature_serialize_der(ctx, der, &len, &sig) && len == 70 && !memcmp(der, want_sig, 70),
          "bip143 signature (RFC6979)");
    secp256k1_context_destroy(ctx);
}

static void test_bip341(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    uint8_t digest[32], sig[65], aux[32] = {0};
    secp256k1_keypair kp;
    plan_t p;

    CHECK(plan_from_tx(TV341_TX, sizeof(TV341_TX), &p), "bip341 parse");
    for (unsigned i = 0; i < p.n_inputs; i++) {
        p.inputs[i].amount = TV341_UTXOS[i].amount;
        set_spk(&p.inputs[i].spk, TV341_UTXOS[i].spk, TV341_UTXOS[i].len);
    }
    for (unsigned s = 0; s < sizeof(TV341_SPENDS) / sizeof(TV341_SPENDS[0]); s++) {
        const typeof(TV341_SPENDS[0]) *v = &TV341_SPENDS[s];
        CHECK(sighash_bip341_keypath(ctx, &p, v->index, v->hash_type, digest) && !memcmp(digest, v->sighash, 32),
              "bip341 sighash input %u type 0x%02x", (unsigned)v->index, v->hash_type);
        CHECK(secp256k1_keypair_create(ctx, &kp, v->tweaked) && secp256k1_schnorrsig_sign32(ctx, sig, digest, &kp, aux)
              && !memcmp(sig, v->sig, 64) && (v->sig_len == 64 || v->sig[64] == v->hash_type),
              "bip341 signature input %u", (unsigned)v->index);
    }
    secp256k1_context_destroy(ctx);
}

/* The smallest transaction carrying amount at output vout, returning its txid */
static size_t make_prevtx(uint8_t *raw, uint32_t vout, uint64_t amount, const uint8_t *spk, size_t spk_len,
                          uint8_t txid[32]) {
    size_t n = 0;
    tx_info_t info;
    static const uint8_t head[] = {2, 0, 0, 0, 1};
    memcpy(raw, head, 5), n = 5;
    memset(raw + n, 0x11, 36), n += 36;
    raw[n++] = 0;
    memset(raw + n, 0xff, 4), n += 4;
    raw[n++] = (uint8_t)(vout + 1);
    for (uint32_t i = 0; i <= vout; i++) {
        uint64_t a = i == vout ? amount : 1000;
        for (int k = 0; k < 8; k++) raw[n++] = (uint8_t)(a >> (8 * k));
        raw[n++] = (uint8_t)spk_len;
        memcpy(raw + n, spk, spk_len), n += spk_len;
    }
    memset(raw + n, 0, 4), n += 4;
    tx_parse(raw, n, NULL, &info);
    memcpy(txid, info.txid, 32);
    return n;
}

static void base_plan(plan_t *p) {
    static const uint8_t ext[22] = {0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    memset(p, 0, sizeof(*p));
    p->magic = PLAN_MAGIC, p->version = PLAN_VERSION, p->tx_version = 2;
    p->n_inputs = 1, p->n_outputs = 2;
    memset(p->inputs[0].prev_txid, 0xaa, 32);
    p->inputs[0].sequence = 0xfffffffd;
    p->inputs[0].amount = 100000;
    set_spk(&p->inputs[0].spk, TV_SPK_P2WPKH_0_0, 22);
    set_key(&p->inputs[0].key, 84 | H, H, H, 0, 0);
    p->inputs[0].sighash_type = 1;
    p->outputs[0].amount = 60000;
    set_spk(&p->outputs[0].spk, ext, 22);
    p->outputs[1].amount = 39000;
    set_spk(&p->outputs[1].spk, TV_SPK_P2WPKH_1_0, 22);
    set_key(&p->outputs[1].key, 84 | H, H, H, 1, 0);
}

static void test_review_and_sign(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    core_prevtx_t prev[PLAN_MAX_INPUTS] = {{0}};
    uint8_t raw0[256], raw1[256], digest[32];
    core_review_t r;
    core_sig_t sigs[PLAN_MAX_INPUTS];
    unsigned n;
    plan_t p, q;

    CHECK(core_review(&(plan_t){0}, NULL, &r) == CORE_ERR_NO_SEED, "no seed");
    CHECK(core_load_seed(TV_SEED) && core_fingerprint() == TV_FP, "fingerprint");

    /* one P2WPKH input, paying out plus change */
    base_plan(&p);
    CHECK(core_review(&p, NULL, &r) == CORE_OK, "p2wpkh review");
    CHECK(r.fee == 1000 && r.owner[0] == CORE_OUT_EXTERNAL && r.owner[1] == CORE_OUT_CHANGE && r.n_sign == 1,
          "p2wpkh change/fee");
    {
        core_display_t d;
        char btc[21];
        CHECK(core_display(&p, &r, &d) == CORE_OK && d.fee == 1000 && d.spend == 60000 && d.n_outputs == 2
              && d.outputs[1].owner == CORE_OUT_CHANGE && d.outputs[1].text_kind == CORE_TEXT_ADDRESS
              && d.outputs[0].text_kind == CORE_TEXT_ADDRESS && !strncmp(d.outputs[0].text, "bc1q", 4), "display");
        core_format_btc(d.spend, btc);
        CHECK(!strcmp(btc, "0.00060000"), "format %s", btc);
    }
    CHECK(core_sign(&p, zero_rng, sigs, &n) == CORE_OK && n == 1, "p2wpkh sign");
    {
        secp256k1_pubkey pub;
        secp256k1_ecdsa_signature sig;
        CHECK(sighash_bip143_p2wpkh(&p, 0, digest) && secp256k1_ec_pubkey_parse(ctx, &pub, sigs[0].pubkey, 33)
              && secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigs[0].sig, sigs[0].sig_len - 1u)
              && secp256k1_ecdsa_verify(ctx, &sig, digest, &pub) && sigs[0].sig[sigs[0].sig_len - 1] == 1,
              "p2wpkh signature verifies");
    }
    CHECK(core_sign(&p, zero_rng, sigs, &n) == CORE_ERR_NOT_REVIEWED, "sign twice needs review");

    /* swapping the plan after review must not produce a signature */
    base_plan(&p);
    core_review(&p, NULL, &r);
    p.outputs[0].amount = 1;
    CHECK(core_sign(&p, zero_rng, sigs, &n) == CORE_ERR_NOT_REVIEWED && n == 0, "plan swapped after review");

    /* claims to be change, but the script is not ours */
    base_plan(&p);
    p.outputs[0].key = p.outputs[1].key;
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.owner[0] == CORE_OUT_EXTERNAL, "fake change is external");

    /* an output on the receive chain is ours, so nothing but the fee is actually spent */
    base_plan(&p);
    set_spk(&p.outputs[0].spk, TV_SPK_P2WPKH_0_1, 22);
    set_key(&p.outputs[0].key, 84 | H, H, H, 0, 1);
    {
        core_display_t d;
        CHECK(core_review(&p, NULL, &r) == CORE_OK && r.owner[0] == CORE_OUT_SELF && core_display(&p, &r, &d) == CORE_OK
              && d.spend == 0 && !strcmp(d.outputs[0].text, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"),
              "self transfer");
    }

    /* past the index limit it no longer counts as our address */
    base_plan(&p);
    p.outputs[1].key.path[4] = 100000;
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.owner[1] == CORE_OUT_EXTERNAL, "change index cap");

    /* OP_RETURN and non-standard scripts are shown whole, in hex */
    base_plan(&p);
    {
        static const uint8_t opret[6] = {0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef}, odd[3] = {0x51, 0x01, 0x02};
        core_display_t d;
        set_spk(&p.outputs[0].spk, opret, 6);
        p.n_outputs = 3;
        set_spk(&p.outputs[2].spk, odd, 3);
        CHECK(core_review(&p, NULL, &r) == CORE_OK && core_display(&p, &r, &d) == CORE_OK
              && d.outputs[0].text_kind == CORE_TEXT_OP_RETURN && !strcmp(d.outputs[0].text, "04deadbeef")
              && d.outputs[2].text_kind == CORE_TEXT_SCRIPT && !strcmp(d.outputs[2].text, "510102"), "opreturn/script");
        p.outputs[0].amount = 0;
        CHECK(core_display(&p, &r, &d) == CORE_ERR_NOT_REVIEWED, "display needs same plan");
    }

    /* change on a different account is not our change */
    base_plan(&p);
    set_spk(&p.outputs[1].spk, TV_SPK_P2WPKH_ACCT1_1_0, 22);
    set_key(&p.outputs[1].key, 84 | H, H, 1 | H, 1, 0);
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.owner[1] == CORE_OUT_EXTERNAL, "other account change is external");

    /* claims our fingerprint, but the key does not produce the script */
    base_plan(&p);
    set_spk(&p.inputs[0].spk, TV_SPK_P2WPKH_0_1, 22);
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_NOT_OURS, "not ours");

    /* sighash type */
    base_plan(&p);
    p.inputs[0].sighash_type = 0;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_SIGHASH, "p2wpkh sighash default rejected");
    base_plan(&p);
    p.inputs[0].sighash_type = 0x83;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_SIGHASH, "p2wpkh acp|single rejected");

    /* malformed */
    base_plan(&p);
    p.outputs[0].spk.bytes[30] = 1;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_FORMAT, "nonzero padding");
    base_plan(&p);
    p.inputs[3].amount = 1;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_FORMAT, "unused input slot");
    base_plan(&p);
    p.outputs[0].amount = 2000000;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_FEE, "outputs exceed inputs");

    /* two inputs including SegWit v0: refused without the previous transaction, and refused if an
     * amount disagrees with it */
    base_plan(&p);
    p.n_inputs = 2;
    p.inputs[1] = p.inputs[0];
    p.inputs[1].amount = 50000;
    set_spk(&p.inputs[1].spk, TV_SPK_P2WPKH_0_1, 22);
    set_key(&p.inputs[1].key, 84 | H, H, H, 0, 1);
    p.outputs[1].amount = 89000;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_PREVTX_MISSING, "fee attack: prevtx required");
    prev[0].len = make_prevtx(raw0, 0, 100000, TV_SPK_P2WPKH_0_0, 22, p.inputs[0].prev_txid);
    prev[0].raw = raw0;
    prev[1].len = make_prevtx(raw1, 2, 50000, TV_SPK_P2WPKH_0_1, 22, p.inputs[1].prev_txid);
    prev[1].raw = raw1;
    p.inputs[1].prev_vout = 2;
    CHECK(core_review(&p, prev, &r) == CORE_OK && r.fee == 1000 && r.n_sign == 2, "fee attack: prevtx verified");
    q = p;
    q.inputs[1].amount = 40000;
    q.outputs[1].amount = 79000;
    CHECK(core_review(&q, prev, &r) == CORE_ERR_PREVTX_MISMATCH, "fee attack: lied amount");
    q = p;
    q.inputs[1].prev_vout = 1;
    CHECK(core_review(&q, prev, &r) == CORE_ERR_PREVTX_MISMATCH, "prevtx wrong vout");
    q = p;
    q.inputs[1].prev_txid[0] ^= 1;
    CHECK(core_review(&q, prev, &r) == CORE_ERR_PREVTX_MISMATCH, "prevtx wrong txid");

    /* P2TR needs no previous transaction even with two inputs, because BIP341 commits to every
     * amount. The signatures are checked against the output key */
    memset(&p, 0, sizeof(p));
    p.magic = PLAN_MAGIC, p.version = PLAN_VERSION, p.tx_version = 2;
    p.n_inputs = 2, p.n_outputs = 1;
    for (unsigned i = 0; i < 2; i++) {
        memset(p.inputs[i].prev_txid, 0xbb + i, 32);
        p.inputs[i].amount = 70000;
        set_spk(&p.inputs[i].spk, i ? TV_SPK_P2TR_0_1 : TV_SPK_P2TR_0_0, 34);
        set_key(&p.inputs[i].key, 86 | H, H, H, 0, i);
        p.inputs[i].sighash_type = (uint8_t)i; /* DEFAULT and ALL */
    }
    p.outputs[0].amount = 139000;
    set_spk(&p.outputs[0].spk, TV_SPK_P2TR_1_0, 34);
    set_key(&p.outputs[0].key, 86 | H, H, H, 1, 0);
    CHECK(core_review(&p, NULL, &r) == CORE_OK && r.owner[0] == CORE_OUT_CHANGE && r.n_sign == 2, "p2tr review");
    CHECK(core_sign(&p, zero_rng, sigs, &n) == CORE_OK && n == 2, "p2tr sign");
    for (unsigned i = 0; i < n; i++) {
        secp256k1_xonly_pubkey xpub;
        CHECK(sighash_bip341_keypath(ctx, &p, i, p.inputs[i].sighash_type, digest)
              && !memcmp(sigs[i].pubkey + 1, p.inputs[i].spk.bytes + 2, 32)
              && secp256k1_xonly_pubkey_parse(ctx, &xpub, sigs[i].pubkey + 1)
              && secp256k1_schnorrsig_verify(ctx, sigs[i].sig, digest, 32, &xpub)
              && sigs[i].sig_len == (i ? 65 : 64), "p2tr signature %u verifies", i);
    }
    p.inputs[0].sighash_type = 0x81;
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_SIGHASH, "p2tr anyonecanpay rejected");

    core_unload();
    CHECK(core_review(&p, NULL, &r) == CORE_ERR_NO_SEED, "unloaded");
    secp256k1_context_destroy(ctx);
}

static void test_address(void) {
    static const struct { const char *addr, *spk; } v350[] = {
        {"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"},
        {"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
        {"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"},
        {"bc1sw50qgdz25j", "6002751e"},
        {"bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"},
        {"tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
        {"tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
        {"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
    };
    /* scripts matching BIP350's invalid examples: 1- and 41-byte programs, 16 bytes at v0, and a push
     * length that disagrees with the script */
    static const char *bad[] = {"510175", "5129751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6aa",
                                "0010751e76e8199196d454941c45d1b3a323", "0015751e76e8199196d454941c45d1b3a323f1433bd6"};
    uint8_t spk[64];
    char out[ADDRESS_MAX];

    for (unsigned i = 0; i < sizeof(v350) / sizeof(v350[0]); i++) {
        size_t n = strlen(v350[i].spk) / 2;
        unhex(v350[i].spk, spk);
        CHECK(address_encode(spk, n, v350[i].addr[0] == 't', out) && !strcmp(out, v350[i].addr),
              "bip350 %u: %s", i, out);
    }
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        unhex(bad[i], spk);
        CHECK(!address_encode(spk, strlen(bad[i]) / 2, 0, out), "invalid program %u encoded as %s", i, out);
    }
    for (unsigned i = 0; i < sizeof(TV_B58) / sizeof(TV_B58[0]); i++)
        CHECK(address_encode(TV_B58[i].spk, TV_B58[i].len, TV_B58[i].testnet, out) && !strcmp(out, TV_B58[i].addr),
              "base58 %u: %s != %s", i, out, TV_B58[i].addr);
    CHECK(address_encode(TV_SPK_P2WPKH_0_0, 22, 0, out) && !strcmp(out, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
          "bip84 address");
    CHECK(address_encode(TV_SPK_P2TR_0_0, 34, 0, out)
          && !strcmp(out, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"), "bip86 address");
}

int main(void) {
    if (!core_init(CORE_MAINNET)) return 1;
    test_bip143();
    test_bip341();
    test_address();
    test_review_and_sign();
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
