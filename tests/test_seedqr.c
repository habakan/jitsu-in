/* SeedQR の読み取りを公式ベクタで確かめる */
#include <stdio.h>
#include <string.h>
#include "seedqr.h"

static int checks, failures;
#define CHECK(cond, ...) do { checks++; if (!(cond)) { failures++; printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } } while (0)

int main(void) {
    char out[256];
    /* BIP39 の全ゼロ: abandon x11 + about。番号は 0,0,...,0,3 */
    const char *d12 = "000000000000000000000000000000000000000000000003";
    const uint8_t e12[16] = {0};
    /* 24 語の全ゼロ: abandon x23 + art（番号 0 x23, 134） */
    const char *d24 = "000000000000000000000000000000000000000000000000"
                      "000000000000000000000000000000000000000000000102";
    const uint8_t e24[32] = {0};
    const char *want12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char *want24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                         "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    char bad[49];

    CHECK(seedqr_decode((const uint8_t *)d12, 48, out, sizeof(out)) > 0 && !strcmp(out, want12), "12 words from digits");
    CHECK(seedqr_decode((const uint8_t *)d24, 96, out, sizeof(out)) > 0 && !strcmp(out, want24), "24 words from digits");
    CHECK(seedqr_decode(e12, 16, out, sizeof(out)) > 0 && !strcmp(out, want12), "12 words from entropy");
    CHECK(seedqr_decode(e24, 32, out, sizeof(out)) > 0 && !strcmp(out, want24), "24 words from entropy");

    /* チェックサムが合わないものは受け取らない */
    memcpy(bad, d12, 49);
    bad[47] = '4';
    CHECK(seedqr_decode((const uint8_t *)bad, 48, out, sizeof(out)) == 0, "bad checksum rejected");
    /* 番号が 2047 を超える、桁が数字でない、長さが違う。
     * 2048 は低位 11bit が 0 と同じなのでチェックサムは通る。範囲検査が無いと単語表の外を読む */
    memcpy(bad, d12, 49);
    bad[0] = '2', bad[1] = '0', bad[2] = '4', bad[3] = '8';
    CHECK(seedqr_decode((const uint8_t *)bad, 48, out, sizeof(out)) == 0, "index 2048 rejected");
    memcpy(bad, d12, 49);
    bad[0] = '9', bad[1] = '9', bad[2] = '9', bad[3] = '9';
    CHECK(seedqr_decode((const uint8_t *)bad, 48, out, sizeof(out)) == 0, "index out of range rejected");
    memcpy(bad, d12, 49);
    bad[5] = 'x';
    CHECK(seedqr_decode((const uint8_t *)bad, 48, out, sizeof(out)) == 0, "non digit rejected");
    CHECK(seedqr_decode((const uint8_t *)d12, 47, out, sizeof(out)) == 0, "odd length rejected");
    CHECK(seedqr_decode((const uint8_t *)d12, 48, out, 50) == 0, "small buffer rejected");

    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures != 0;
}
