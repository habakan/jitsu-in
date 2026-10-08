/* The entry points of signer.wasm. It takes the plan_t parser.wasm produced, re-derives the keys to
 * check it, and returns signatures. Every judgement lives in core.c; this file is only the handover
 * to the host, laid out the way parser.wasm's ABI is */
#include <string.h>
#include "core.h"
#include "seedqr.h"
#include "sha512.h"
#include "wipe.h"

#ifdef __wasm__
#define EXPORT(name) __attribute__((export_name(#name))) name
#else
#define EXPORT(name) name
#endif

#define PREVTX_MAX 32768

/* Three return conventions, and which one a function uses follows from what it does:
 *   init / seed / seedqr / load_seed / set_prevtx  1 on success, 0 on failure (they can only fail one way)
 *   review / display / xpub               CORE_OK (0) on success, CORE_ERR_* otherwise
 *   sign                                  the number of signatures, or -CORE_ERR_*
 *   find_address                          chain << 20 | index, or -CORE_ERR_*
 * Buffer accessors return a pointer, fingerprint returns the value, unload returns nothing. */

/* Where the host writes. All static: this module never allocates */
static plan_t plan;
static uint8_t prevtx_buf[PREVTX_MAX];
static core_prevtx_t prevtx[PLAN_MAX_INPUTS];
static core_review_t review;
static core_display_t display;
static core_sig_t sigs[PLAN_MAX_INPUTS];
static uint8_t in[512]; /* a mnemonic or SeedQR || passphrase, a seed, entropy or dice; always wiped after */
static char xpub[CORE_XPUB_MAX], desc[CORE_DESC_MAX];
static char mnemonic[256]; /* a newly made mnemonic, until the host has read it */

unsigned char *EXPORT(signer_input)(void) {
    return in;
}
/* So a host can bounds-check before writing, as parser.wasm's parser_input_cap lets it */
unsigned int EXPORT(signer_input_cap)(void) {
    return (unsigned int)sizeof(in);
}
plan_t *EXPORT(signer_plan)(void) {
    return &plan;
}
unsigned char *EXPORT(signer_prevtx)(void) {
    return prevtx_buf;
}
core_review_t *EXPORT(signer_review_output)(void) {
    return &review;
}
core_display_t *EXPORT(signer_display_output)(void) {
    return &display;
}
core_sig_t *EXPORT(signer_sigs)(void) {
    return sigs;
}
char *EXPORT(signer_xpub_output)(void) {
    return xpub;
}
char *EXPORT(signer_desc_output)(void) {
    return desc;
}
char *EXPORT(signer_mnemonic_output)(void) {
    return mnemonic;
}

int EXPORT(signer_init)(int testnet) {
    memset(prevtx, 0, sizeof(prevtx));
    return core_init(testnet ? CORE_TESTNET : CORE_MAINNET);
}

/* Build the key from the mnemonic and passphrase written to in. PBKDF2 2048 rounds takes about half
 * a second, in a browser as on the device */
static int seed_from(const uint8_t *mn, size_t mn_len, const uint8_t *pass, size_t pass_len) {
    uint8_t salt[8 + sizeof(in)], seed[64];
    int ok;
    memcpy(salt, "mnemonic", 8);
    memcpy(salt + 8, pass, pass_len);
    pbkdf2_hmac_sha512(mn, mn_len, salt, 8 + pass_len, 2048, seed);
    ok = core_load_seed(seed);
    wipe(salt, sizeof(salt));
    wipe(seed, sizeof(seed));
    return ok;
}

/* English BIP39 only, and the checksum has to hold: a typo is refused rather than becoming a wallet.
 * Whitespace and capitals are normalised first; the passphrase is used exactly as given */
int EXPORT(signer_seed_from_mnemonic)(unsigned mn_len, unsigned pass_len) {
    size_t n = 0;
    int ok = mn_len <= sizeof(in) && pass_len <= sizeof(in) - mn_len;
    if (ok) n = bip39_normalize(in, mn_len, in);
    ok = ok && bip39_mnemonic_ok(in, n) && seed_from(in, n, in + mn_len, pass_len);
    wipe(in, sizeof(in));
    return ok;
}

/* in holds the SeedQR payload, then the passphrase. The words are rebuilt here and never returned:
 * the host confirms what it loaded by showing the fingerprint */
int EXPORT(signer_seed_from_seedqr)(unsigned qr_len, unsigned pass_len) {
    char mn[256];
    int n = 0, ok = 0;
    if (qr_len <= sizeof(in) && pass_len <= sizeof(in) - qr_len) n = seedqr_decode(in, qr_len, mn, sizeof(mn));
    if (n > 0) ok = seed_from((const uint8_t *)mn, (size_t)n, in + qr_len, pass_len);
    wipe(mn, sizeof(mn));
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
    wipe(mnemonic, sizeof(mnemonic));
}

unsigned EXPORT(signer_fingerprint)(void) {
    return core_fingerprint();
}

/* Where input i's non_witness_utxo sits inside prevtx_buf. A len of 0 means it has none */
int EXPORT(signer_set_prevtx)(unsigned i, unsigned off, unsigned len) {
    if (i >= PLAN_MAX_INPUTS || off > PREVTX_MAX || len > PREVTX_MAX - off) return 0;
    prevtx[i].raw = len ? prevtx_buf + off : 0;
    prevtx[i].len = len;
    return 1;
}

int EXPORT(signer_review)(void) {
    return core_review(&plan, prevtx, &review);
}
int EXPORT(signer_display)(void) {
    return core_display(&plan, &review, &display);
}

/* Sign and return how many. A negative result is -CORE_ERR_*. No rng is passed — that would mean an
 * import — so the secp256k1 context is not blinded here. Power analysis is a concern on the device,
 * and the device runs this same core natively, where it does blind */
int EXPORT(signer_sign)(void) {
    unsigned n = 0;
    int rc = core_sign(&plan, 0, sigs, &n);
    return rc ? -rc : (int)n;
}

/* On a refusal nothing from an earlier call is left to be read as this one's */
int EXPORT(signer_xpub)(unsigned purpose, unsigned account) {
    int rc = core_account_xpub(purpose, account, xpub, desc);
    if (rc) wipe(xpub, sizeof(xpub)), wipe(desc, sizeof(desc));
    return rc;
}

/* in holds the address. Nothing secret, but cleared like every other use of in */
int EXPORT(signer_find_address)(unsigned len, unsigned account, unsigned count) {
    int rc = len <= sizeof(in) ? core_find_address((const char *)in, len, account, count) : -CORE_ERR_FORMAT;
    wipe(in, sizeof(in));
    return rc;
}

/* A new mnemonic from the entropy in in, or from dice rolls (1 to 6) in in. Returns its length in
 * signer_mnemonic_output(), or 0. Nothing is loaded: the words are to be written down first */
int EXPORT(signer_mnemonic_from_entropy)(unsigned len) {
    int n;
    wipe(mnemonic, sizeof(mnemonic));
    n = len <= sizeof(in) ? bip39_mnemonic_from_entropy(in, len, mnemonic, sizeof(mnemonic)) : 0;
    if (!n) wipe(mnemonic, sizeof(mnemonic));
    wipe(in, sizeof(in));
    return n;
}

int EXPORT(signer_mnemonic_from_dice)(unsigned len, unsigned words) {
    int n;
    wipe(mnemonic, sizeof(mnemonic));
    n = len <= sizeof(in) ? bip39_mnemonic_from_dice(in, len, words, mnemonic, sizeof(mnemonic)) : 0;
    if (!n) wipe(mnemonic, sizeof(mnemonic));
    wipe(in, sizeof(in));
    return n;
}
