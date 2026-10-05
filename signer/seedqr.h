#ifndef CORE_SEEDQR_H
#define CORE_SEEDQR_H

/* Reads a SeedQR back into a mnemonic. It carries the secret, so it never goes through the parser */

#include <stddef.h>
#include <stdint.h>

/* Accepts a standard SeedQR (four digits per word, 12 or 24 words) or a CompactSeedQR (16 or 32 bytes
 * of entropy). Returns the mnemonic's length and writes it NUL-terminated to out, or 0 if the BIP39
 * checksum does not hold */
int seedqr_decode(const uint8_t *payload, size_t len, char *out, size_t cap);

#endif
