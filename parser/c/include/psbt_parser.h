#ifndef PSBT_PARSER_H
#define PSBT_PARSER_H

/* Exports of parser.wasm. The host receives the addresses of exported buffers and bounds-checks them before access.
 * Flow: write the PSBT to parser_input() -> parser_parse() -> read parser_plan() / parser_prevtx_*()
 *       -> the host writes signatures to parser_sigs() -> parser_finalize() -> read parser_output() */

#include "plan.h"

#define PSBT_MAX 32768
#define PSBT_OUT_MAX (PSBT_MAX + PLAN_MAX_INPUTS * 128)

enum {
    P_OK = 0,
    P_ERR_MAGIC,
    P_ERR_FORMAT,      /* BIP174 violation (key / value lengths, v2-only fields, trailing bytes, ...) */
    P_ERR_DUPLICATE,   /* duplicate key within a map */
    P_ERR_TX,          /* no unsigned tx, scriptSig / witness present, non-canonical serialization */
    P_ERR_UNSUPPORTED, /* PSBT v2, script longer than PLAN_MAX_SPK, sighash that does not fit in a byte */
    P_ERR_LIMIT,       /* more inputs / outputs than PLAN_MAX_*, PSBT larger than PSBT_MAX */
    P_ERR_UTXO,        /* input without utxo data, non_witness_utxo txid / output mismatch */
    P_ERR_SIG,         /* invalid signatures passed to finalize */
};

unsigned char *parser_input(void);
unsigned parser_input_cap(void);
/* fingerprint is the signer's master fingerprint (not a secret). Only derivations with it become key candidates */
int parser_parse(unsigned len, unsigned fingerprint);
plan_t *parser_plan(void);
/* Offset and length of input i's non_witness_utxo within parser_input(); length 0 if absent */
unsigned parser_prevtx_off(unsigned i);
unsigned parser_prevtx_len(unsigned i);
plan_sig_t *parser_sigs(void);
/* Inserts the n signatures written to parser_sigs() and returns the signed PSBT length, or -P_ERR_SIG */
int parser_finalize(unsigned n);
unsigned char *parser_output(void);

/* Animated QR: reset, then for each QR payload write it to parser_input() and call parser_ur_receive(len).
 * A positive result is the PSBT length, with the PSBT already in parser_input() for parser_parse().
 * Negative results are UR_ERR_* from ur.h */
void parser_ur_reset(void);
int parser_ur_receive(unsigned len);
unsigned parser_ur_progress(void);
/* Signed PSBT as an animated QR: parser_ur_encode_start(len returned by parser_finalize(), max fragment bytes),
 * then parser_ur_encode_next() for each frame, reading the text from parser_input() */
int parser_ur_encode_start(unsigned len, unsigned max_fragment_len);
int parser_ur_encode_next(void);

#endif
