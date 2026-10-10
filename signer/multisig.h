#ifndef CORE_MULTISIG_H
#define CORE_MULTISIG_H

/* A P2WSH sortedmulti wallet of at most three keys, read from a coordinator's descriptor, BSMS record or
 * Coldcard-style setup file. Only public keys: core.c decides which of them is ours */

#include <stddef.h>
#include <stdint.h>
#include "plan.h"
#include "address.h"

#define MS_MAX_KEYS 3
#define MS_MAX_DEPTH (PLAN_MAX_DEPTH - 2) /* the origin path, leaving room for chain and index */
#define MS_DESC_MAX 640

typedef struct {
    uint32_t fingerprint;
    uint32_t path[MS_MAX_DEPTH]; /* all hardened */
    uint8_t depth;
    uint8_t ser[78]; /* the xpub as serialized: chain code at 13, public key at 45 */
} ms_key_t;

typedef struct {
    uint8_t threshold, n;
    ms_key_t keys[MS_MAX_KEYS];
} ms_wallet_t;

/* 1 on success. address is the first receive address a BSMS record states, or empty */
int ms_parse(const char *s, size_t len, int testnet, ms_wallet_t *w, char address[ADDRESS_MAX]);
/* The witness script at chain/index, keys sorted as sortedmulti() sorts them */
int ms_wscript(const ms_wallet_t *w, uint32_t chain, uint32_t index, plan_wscript_t *out);
/* wsh(sortedmulti(...)) with xpub / tpub, <0;1> children and its checksum. Returns its length, or 0 */
size_t ms_descriptor(const ms_wallet_t *w, int testnet, char out[MS_DESC_MAX]);

#endif
