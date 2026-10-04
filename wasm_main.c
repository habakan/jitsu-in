/* The entry points of signer.wasm. It takes the plan_t parser.wasm produced, re-derives the keys to
 * check it, and returns signatures. Every judgement lives in core.c; this file is only the handover
 * to the host, laid out the way parser.wasm's ABI is */
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

/* Where the host writes. All static: this module never allocates */
static plan_t plan;
static uint8_t prevtx_buf[PREVTX_MAX];
static core_prevtx_t prevtx[PLAN_MAX_INPUTS];
static core_review_t review;
static core_display_t display;
static core_sig_t sigs[PLAN_MAX_INPUTS];
static uint8_t in[512];   /* mnemonic || passphrase, or a 64-byte seed */
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

/* Build the key from the mnemonic and passphrase written to in. PBKDF2 2048 rounds takes about half
 * a second, in a browser as on the device */
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

/* Use the first 64 bytes of in as the seed */
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

/* Where input i's non_witness_utxo sits inside prevtx_buf. A len of 0 means it has none */
int EXPORT(signer_set_prevtx)(unsigned i, unsigned off, unsigned len) {
    if (i >= PLAN_MAX_INPUTS || off > PREVTX_MAX || len > PREVTX_MAX - off) return 0;
    prevtx[i].raw = len ? prevtx_buf + off : 0;
    prevtx[i].len = len;
    return 1;
}

int EXPORT(signer_review)(void) { return core_review(&plan, prevtx, &review); }
int EXPORT(signer_display)(void) { return core_display(&plan, &review, &display); }

/* Sign and return how many. A negative result is -CORE_ERR_*. No rng is passed — that would mean an
 * import — so the secp256k1 context is not blinded here. Power analysis is a concern on the device,
 * and the device runs this same core natively, where it does blind */
int EXPORT(signer_sign)(void) {
    unsigned n = 0;
    int rc = core_sign(&plan, 0, sigs, &n);
    return rc ? -rc : (int)n;
}

int EXPORT(signer_xpub)(void) { return core_account_xpub(xpub, desc); }
