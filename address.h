#ifndef CORE_ADDRESS_H
#define CORE_ADDRESS_H

#include <stddef.h>
#include <stdint.h>

/* scriptPubKey を標準のアドレス文字列にする。P2PKH / P2SH は base58check、witness v0 は bech32、
 * v1〜v16 は bech32m（BIP173 / BIP350）。標準形でなければ 0 を返し、呼び出し側はスクリプトを 16 進で見せる */
#define ADDRESS_MAX 75 /* v1〜v16 の 40 byte プログラム: hrp 2 + '1' + 65 + checksum 6 + NUL */

int address_encode(const uint8_t *spk, size_t len, int testnet, char out[ADDRESS_MAX]);

/* 末尾に 4 byte のチェックサムを足して base58 にする。xpub（78 byte）もこれで作る */
#define BASE58CHECK_MAX_IN 78
#define BASE58CHECK_MAX_OUT 120
void base58check_data(const uint8_t *p, size_t n, char *out);

#endif
