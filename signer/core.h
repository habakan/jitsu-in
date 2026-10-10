#ifndef CORE_CORE_H
#define CORE_CORE_H

/* The part that holds keys (docs/architecture-b.md §5, §6). plan_t is untrusted input from
 * parser.wasm: the caller passes a copy it made on the native side. core_sign() refuses to sign
 * anything but the exact plan core_review() was shown, which is what binds the screen to the signature */

#include <stddef.h>
#include <stdint.h>
#include "plan.h"
#include "address.h"

enum {
    CORE_OK = 0,
    CORE_ERR_FORMAT, /* over a limit, an unused field is non-zero, or an amount is out of range */
    CORE_ERR_NO_SEED,
    CORE_ERR_NOT_OURS, /* an input claims our fingerprint, but its key does not produce its script */
    CORE_ERR_NOTHING_TO_SIGN,
    CORE_ERR_SIGHASH,        /* a sighash type we do not allow */
    CORE_ERR_SCRIPT,         /* an input to be signed is not P2WPKH, P2SH-P2WPKH, P2TR or a P2WSH multisig */
    CORE_ERR_PREVTX_MISSING, /* two or more inputs including SegWit v0, and no non_witness_utxo */
    CORE_ERR_PREVTX_MISMATCH,
    CORE_ERR_FEE,
    CORE_ERR_NOT_REVIEWED,
    CORE_ERR_CRYPTO,
    CORE_ERR_NOT_FOUND, /* core_find_address: none of the addresses searched is this one */
};

typedef enum { CORE_MAINNET = 0, CORE_TESTNET = 1 } core_network_t;

typedef struct {
    const uint8_t *raw; /* the non_witness_utxo, or NULL if the PSBT carried none */
    size_t len;
} core_prevtx_t;

/* Who an output belongs to. CHANGE and SELF are only ever set after re-deriving the key here and
 * confirming it produces that script */
enum { CORE_OUT_EXTERNAL = 0, CORE_OUT_CHANGE, CORE_OUT_SELF };

typedef struct {
    uint64_t total_in, total_out, fee;
    uint8_t owner[PLAN_MAX_OUTPUTS];
    uint8_t will_sign[PLAN_MAX_INPUTS];
    uint8_t n_sign;
} core_review_t;

/* What the review screens show. Every string is built here from the plan's bytes, never taken from it */
enum { CORE_TEXT_ADDRESS = 0, CORE_TEXT_OP_RETURN, CORE_TEXT_SCRIPT };

typedef struct {
    uint64_t amount;
    uint8_t owner, text_kind;
    char text[2 * PLAN_MAX_SPK + 1]; /* an address, or hex of the OP_RETURN data or the whole script */
} core_display_output_t;

typedef struct {
    uint64_t fee, spend; /* spend is the total of external outputs; ours and change are excluded */
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
/* BTC with eight decimals (60000 -> "0.00060000") */
void core_format_btc(uint64_t sats, char out[21]);

/* The BIP85 child mnemonic (English, 12, 18 or 24 words, index below 2^31) of the loaded seed. Returns
 * its length, NUL-terminated in out, or 0 */
int core_bip85_mnemonic(unsigned words, uint32_t index, char *out, size_t cap);

/* Where on m/purpose'/coin'/account' an address is: receive then change, indices below count, as chain << 20 |
 * index, or -CORE_ERR_*. 3/2 (P2SH) is purpose 49, bc1q/tb1q 84, bc1p/tb1p 86; any other is CORE_ERR_FORMAT */
int core_find_address(const char *addr, size_t len, uint32_t account, uint32_t count);

/* The account xpub (m/purpose'/coin'/account') and its sh(wpkh()), wpkh() or tr() descriptor, so the PC
 * side can be watch-only. purpose is 48, 49, 84 or 86 and account below 2^31; 48 is m/48'/coin'/account'/2'
 * (P2WSH) and gives the key expression for sortedmulti(). CORE_OK, or _FORMAT / _NO_SEED */
#define CORE_XPUB_MAX 120
#define CORE_DESC_MAX 180
/* BIP137, purpose 49 or 84. Review shows the key's address and the message, in hex unless it is printable
 * ASCII, since other bytes could render as something else; sign then signs that message, once */
#define CORE_MESSAGE_MAX 512
enum { CORE_TEXT_MESSAGE = 0, CORE_TEXT_HEX };
typedef struct {
    char address[ADDRESS_MAX];
    uint8_t text_kind;
    char text[2 * CORE_MESSAGE_MAX + 1];
} core_message_t;
int core_message_review(const uint8_t *msg, size_t len, unsigned purpose, uint32_t account, uint32_t chain,
                        uint32_t index, core_message_t *out);
/* 65 bytes: the BIP137 header (35-38 P2SH-P2WPKH, 39-42 P2WPKH), then r and s */
int core_message_sign(uint8_t sig[65]);

int core_account_xpub(unsigned purpose, uint32_t account, char out[CORE_XPUB_MAX], char desc[CORE_DESC_MAX]);

#endif
