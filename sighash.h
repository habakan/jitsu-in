#ifndef CORE_SIGHASH_H
#define CORE_SIGHASH_H

#include "plan.h"
#include "secp256k1.h"

/* BIP143 P2WPKH, SIGHASH_ALL only */
int sighash_bip143_p2wpkh(const plan_t *p, unsigned index, uint8_t out[32]);
/* BIP341 key path, no annex. hash_type is one of the seven BIP341 defines */
int sighash_bip341_keypath(const secp256k1_context *ctx, const plan_t *p, unsigned index, uint8_t hash_type,
                           uint8_t out[32]);

#endif
