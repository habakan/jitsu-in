/* bitcoin-signer.wasm の入口。parser.wasm が作った plan_t を受け取り、鍵を再導出して検証し、署名を返す。
 * 判断は core.c が持つ。ここはホストとの受け渡しだけを並べる（docs/abi.md と対になる形） */
#include <string.h>
#include "core.h"
#include "sha512.h"
#include "wipe.h"

#ifdef __wasm__
#define EXPORT(name) __attribute__((export_name(#name))) name
#else
#define EXPORT(name) name
#endif

#define PREVTX_MAX 32768

/* ホストが書き込む領域。すべて静的で、割り当ては一切しない */
static plan_t plan;
static uint8_t prevtx_buf[PREVTX_MAX];
static core_prevtx_t prevtx[PLAN_MAX_INPUTS];
static core_review_t review;
static core_display_t display;
static core_sig_t sigs[PLAN_MAX_INPUTS];
static uint8_t in[512];   /* ニーモニック‖パスフレーズ、または 64 byte の seed */
static char xpub[CORE_XPUB_MAX], desc[CORE_DESC_MAX];

unsigned char *EXPORT(signer_in)(void) { return in; }
plan_t *EXPORT(signer_plan)(void) { return &plan; }
unsigned char *EXPORT(signer_prevtx)(void) { return prevtx_buf; }
core_review_t *EXPORT(signer_review_out)(void) { return &review; }
core_display_t *EXPORT(signer_display_out)(void) { return &display; }
core_sig_t *EXPORT(signer_sigs)(void) { return sigs; }
char *EXPORT(signer_xpub_out)(void) { return xpub; }
char *EXPORT(signer_desc_out)(void) { return desc; }

int EXPORT(signer_init)(int testnet) {
    memset(prevtx, 0, sizeof(prevtx));
    return core_init(testnet ? CORE_TESTNET : CORE_MAINNET);
}

/* in に書いたニーモニックとパスフレーズから鍵を作る。PBKDF2 2048 回はブラウザでも 0.5 秒ほど */
int EXPORT(signer_seed_from_mnemonic)(unsigned mn_len, unsigned pass_len) {
    uint8_t salt[8 + sizeof(in)], seed[64];
    int ok = 0;
    if (mn_len + pass_len <= sizeof(in)) {
        memcpy(salt, "mnemonic", 8);
        memcpy(salt + 8, in + mn_len, pass_len);
        pbkdf2_hmac_sha512(in, mn_len, salt, 8 + pass_len, 2048, seed);
        ok = core_load_seed(seed);
    }
    wipe(salt, sizeof(salt));
    wipe(seed, sizeof(seed));
    wipe(in, sizeof(in));
    return ok;
}

/* in の先頭 64 byte を seed として使う */
int EXPORT(signer_load_seed)(void) {
    int ok = core_load_seed(in);
    wipe(in, sizeof(in));
    return ok;
}

void EXPORT(signer_unload)(void) {
    core_unload();
    wipe(&plan, sizeof(plan));
    wipe(prevtx_buf, sizeof(prevtx_buf));
    wipe(sigs, sizeof(sigs));
    wipe(&display, sizeof(display));
}

unsigned EXPORT(signer_fingerprint)(void) { return core_fingerprint(); }

/* 入力 i の non_witness_utxo が prevtx_buf のどこにあるか。len が 0 なら無し */
int EXPORT(signer_set_prevtx)(unsigned i, unsigned off, unsigned len) {
    if (i >= PLAN_MAX_INPUTS || off > PREVTX_MAX || len > PREVTX_MAX - off) return 0;
    prevtx[i].raw = len ? prevtx_buf + off : 0;
    prevtx[i].len = len;
    return 1;
}

int EXPORT(signer_review)(void) { return core_review(&plan, prevtx, &review); }
int EXPORT(signer_display)(void) { return core_display(&plan, &review, &display); }

/* 署名して本数を返す。負なら CORE_ERR_*。rng は渡さない（import を増やさないため）ので
 * context のブラインド化は効かない。電力解析が関係するのは実機の側で、そちらはネイティブが行う */
int EXPORT(signer_sign)(void) {
    unsigned n = 0;
    int rc = core_sign(&plan, 0, sigs, &n);
    return rc ? -rc : (int)n;
}

int EXPORT(signer_xpub)(void) { return core_account_xpub(xpub, desc); }
