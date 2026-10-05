#ifndef CORE_HASH_H
#define CORE_HASH_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

void ripemd160(const uint8_t *p, size_t n, uint8_t out[20]);
void hash160(const uint8_t *p, size_t n, uint8_t out[20]);

#endif
