#ifndef CORE_SEEDQR_H
#define CORE_SEEDQR_H

/* SeedQR を読んでニーモニックに戻す。秘密を運ぶので解析器（WASM）には渡さない */

#include <stddef.h>
#include <stdint.h>

/* 標準 SeedQR（4 桁 x 12 または 24 語の数字列）と CompactSeedQR（16 / 32 byte のエントロピー）を受ける。
 * BIP39 のチェックサムが合えばニーモニックの長さを返し、out に NUL 終端で書く。合わなければ 0 */
int seedqr_decode(const uint8_t *payload, size_t len, char *out, size_t cap);

#endif
