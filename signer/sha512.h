#ifndef SIGNER_SHA512_H
#define SIGNER_SHA512_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t s[8];
    uint64_t len;
    unsigned char buf[128];
} sha512_ctx;

typedef struct {
    sha512_ctx inner, outer;
} hmac_sha512_ctx;

void sha512_compress(uint64_t s[8], const unsigned char block[128]);
void sha512_init(sha512_ctx *c);
void sha512_update(sha512_ctx *c, const unsigned char *p, size_t n);
void sha512_final(sha512_ctx *c, unsigned char out[64]);
void hmac_sha512_init(hmac_sha512_ctx *h, const unsigned char *key, size_t keylen);
void hmac_sha512_final(hmac_sha512_ctx *h, unsigned char out[64]);
void pbkdf2_hmac_sha512(const unsigned char *pw, size_t pwlen, const unsigned char *salt, size_t saltlen,
                        unsigned iter, unsigned char out[64]);

#endif
