#ifndef CORE_CORE_H
#define CORE_CORE_H

/* 鍵を持つ署名中核（docs/architecture-b.md §5, §6）。plan_t は parser.wasm から来る untrusted な入力で、
 * 呼び出し側はネイティブ側にコピーしたものを渡す。core_review() で確認した plan と同じものしか core_sign() は署名しない */

#include <stddef.h>
#include <stdint.h>
#include "plan.h"

enum {
    CORE_OK = 0,
    CORE_ERR_FORMAT,       /* 上限超過、未使用フィールドが非ゼロ、額の範囲外 */
    CORE_ERR_NO_SEED,
    CORE_ERR_NOT_OURS,     /* 自分の fingerprint を名乗る入力の鍵とスクリプトが一致しない */
    CORE_ERR_NOTHING_TO_SIGN,
    CORE_ERR_SIGHASH,      /* 許可しない sighash type */
    CORE_ERR_SCRIPT,       /* 署名対象の入力が P2WPKH / P2TR 以外 */
    CORE_ERR_PREVTX_MISSING, /* SegWit v0 を含む 2 入力以上で non_witness_utxo が無い */
    CORE_ERR_PREVTX_MISMATCH,
    CORE_ERR_FEE,
    CORE_ERR_NOT_REVIEWED,
    CORE_ERR_CRYPTO,
};

typedef enum { CORE_MAINNET = 0, CORE_TESTNET = 1 } core_network_t;

typedef struct {
    const uint8_t *raw; /* non_witness_utxo。無ければ NULL */
    size_t len;
} core_prevtx_t;

/* 出力の持ち主。CHANGE / SELF はネイティブが鍵を再導出してスクリプトの一致を確かめたものだけ */
enum { CORE_OUT_EXTERNAL = 0, CORE_OUT_CHANGE, CORE_OUT_SELF };

typedef struct {
    uint64_t total_in, total_out, fee;
    uint8_t owner[PLAN_MAX_OUTPUTS];
    uint8_t will_sign[PLAN_MAX_INPUTS];
    uint8_t n_sign;
} core_review_t;

/* 確認画面に出す内容。文字列はすべてネイティブが plan のバイト列から作る */
enum { CORE_TEXT_ADDRESS = 0, CORE_TEXT_OP_RETURN, CORE_TEXT_SCRIPT };

typedef struct {
    uint64_t amount;
    uint8_t owner, text_kind;
    char text[2 * PLAN_MAX_SPK + 1]; /* アドレス、または OP_RETURN のデータ / スクリプト全体の 16 進 */
} core_display_output_t;

typedef struct {
    uint64_t fee, spend; /* spend は外部出力の合計。自分宛て・お釣りは含めない */
    uint8_t n_outputs;
    core_display_output_t outputs[PLAN_MAX_OUTPUTS];
} core_display_t;

typedef plan_sig_t core_sig_t;

typedef int (*core_rng_t)(uint8_t *buf, size_t len);

int core_init(core_network_t net);
int core_load_seed(const uint8_t seed[64]);
void core_unload(void);
uint32_t core_fingerprint(void);
int core_review(const plan_t *p, const core_prevtx_t prev[PLAN_MAX_INPUTS], core_review_t *r);
int core_display(const plan_t *p, const core_review_t *r, core_display_t *d);
int core_sign(const plan_t *p, core_rng_t rng, core_sig_t sigs[PLAN_MAX_INPUTS], unsigned *n_sigs);
/* 8 桁の小数で BTC 表記にする（例: 60000 -> "0.00060000"） */
void core_format_btc(uint64_t sats, char out[21]);

/* 口座の拡張公開鍵（m/84'/coin'/0'）と出力ディスクリプタ。PC 側をウォッチオンリーにするために渡す */
#define CORE_XPUB_MAX 120
#define CORE_DESC_MAX 180
int core_account_xpub(char out[CORE_XPUB_MAX], char desc[CORE_DESC_MAX]);

#endif
