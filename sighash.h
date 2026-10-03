#ifndef CORE_SIGHASH_H
#define CORE_SIGHASH_H

#include "plan.h"
#include "secp256k1.h"

/* BIP143 の P2WPKH、SIGHASH_ALL のみ */
int sighash_bip143_p2wpkh(const plan_t *p, unsigned index, uint8_t out[32]);
/* BIP341 の key path（annex なし）。hash_type は BIP341 が定める 7 種類 */
int sighash_bip341_keypath(const secp256k1_context *ctx, const plan_t *p, unsigned index, uint8_t hash_type,
                           uint8_t out[32]);

#endif
