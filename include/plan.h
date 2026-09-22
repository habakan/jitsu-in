#ifndef HOST_ABI_PLAN_H
#define HOST_ABI_PLAN_H

/* Structured form of a transaction that parser.wasm hands to the signer.
 * No pointers or longs, so wasm32, rv32 and 64-bit hosts share the same layout */

#include <stddef.h>
#include <stdint.h>

#define PLAN_MAGIC       0x4e4c5042u /* "BPLN" */
#define PLAN_VERSION     1
#define PLAN_MAX_INPUTS  16
#define PLAN_MAX_OUTPUTS 16
#define PLAN_MAX_SPK     83 /* standard OP_RETURN limit; P2TR / P2WSH are 34 */
#define PLAN_MAX_DEPTH   8

typedef struct {
    uint8_t len;
    uint8_t bytes[PLAN_MAX_SPK];
} plan_script_t;

typedef struct {
    uint8_t depth;
    uint32_t fingerprint; /* first 4 bytes of HASH160(master pubkey) read big-endian (73c5da0a -> 0x73c5da0a) */
    uint32_t path[PLAN_MAX_DEPTH];
} plan_keypath_t;

typedef struct {
    uint8_t prev_txid[32]; /* internal byte order (as serialized) */
    uint32_t prev_vout;
    uint32_t sequence;
    uint64_t amount;    /* witness_utxo */
    plan_script_t spk;  /* witness_utxo */
    plan_keypath_t key; /* depth = 0 for inputs not to be signed */
    uint8_t sighash_type;
} plan_input_t;

typedef struct {
    uint64_t amount;
    plan_script_t spk;
    plan_keypath_t key; /* change candidate; the signer re-derives the key to confirm it */
} plan_output_t;

typedef struct {
    uint32_t magic, version;
    int32_t tx_version;
    uint32_t locktime;
    uint8_t n_inputs, n_outputs;
    plan_input_t inputs[PLAN_MAX_INPUTS];
    plan_output_t outputs[PLAN_MAX_OUTPUTS];
} plan_t;

/* A signature made by the signer. The host writes it to parser.wasm's signature buffer and parser.wasm inserts it */
typedef struct {
    uint8_t input;
    uint8_t pubkey[33]; /* compressed pubkey for P2WPKH; 0x00 + x-only output key for P2TR */
    uint8_t sig_len;
    uint8_t sig[73];    /* DER + sighash byte for ECDSA; 64 or 65 bytes for Schnorr */
} plan_sig_t;

_Static_assert(sizeof(plan_sig_t) == 108, "plan_sig_t layout");
_Static_assert(sizeof(plan_input_t) == 176, "plan_input_t layout");
_Static_assert(sizeof(plan_output_t) == 136, "plan_output_t layout");
_Static_assert(offsetof(plan_t, inputs) == 24, "plan_t layout");
_Static_assert(sizeof(plan_t) == 5016, "plan_t layout");

#endif
