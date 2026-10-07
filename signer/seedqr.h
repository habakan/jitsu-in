#ifndef CORE_SEEDQR_H
#define CORE_SEEDQR_H

/* Reads a SeedQR back into a mnemonic. It carries the secret, so it never goes through the parser */

#include <stddef.h>
#include <stdint.h>

/* Accepts a standard SeedQR (four digits per word, 12 or 24 words) or a CompactSeedQR (16 or 32 bytes
 * of entropy). Returns the mnemonic's length and writes it NUL-terminated to out, or 0 if the BIP39
 * checksum does not hold */
int seedqr_decode(const uint8_t *payload, size_t len, char *out, size_t cap);

/* 1 if mn is 12, 15, 18, 21 or 24 English BIP39 words, lower case, one space apart, whose checksum
 * holds. Other wordlists are refused, so a typo cannot pass as a mnemonic in another language */
int bip39_mnemonic_ok(const uint8_t *mn, size_t len);

/* The SeedQR for a 12 or 24 word mnemonic: the Standard digits (48 or 96 ASCII bytes), or with compact
 * the CompactSeedQR's raw entropy (16 or 32 bytes). Returns its length, or 0 */
int seedqr_encode(const uint8_t *mn, size_t len, int compact, uint8_t *out, size_t cap);

/* The mnemonic for 16, 20, 24, 28 or 32 bytes of entropy, written NUL-terminated to out. Returns its
 * length, or 0 for another length or too small a buffer */
int bip39_mnemonic_from_entropy(const uint8_t *ent, size_t len, char *out, size_t cap);

/* Dice rolls as the characters 1 to 6, at least 50 for 12 words and 99 for 24 so that the rolls carry
 * the entropy they stand for. The entropy is SHA-256 of the rolls, cut to 16 bytes for 12 words */
int bip39_mnemonic_from_dice(const uint8_t *rolls, size_t len, unsigned words, char *out, size_t cap);

#endif
