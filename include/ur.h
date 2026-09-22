#ifndef UR_H
#define UR_H

/* Uniform Resources (BCR-2020-005) decoding: single-part and fountain-coded multipart URs whose parts
 * arrive as QR payload strings. Everything is in static buffers with fixed limits; nothing allocates. */

#include <stddef.h>
#include <stdint.h>

#define UR_MAX_SEQ_LEN 1024        /* parts a message may be split into */
#define UR_MAX_MIXED 64            /* mixed parts kept while waiting for reduction */
#define UR_MIXED_POOL 16384        /* bytes shared by the kept mixed parts */

enum {
    UR_ERR_SCHEME = -1,     /* not "ur:<type>/..." */
    UR_ERR_BYTEWORDS = -2,  /* invalid characters or CRC32 */
    UR_ERR_PART = -3,       /* malformed part CBOR or sequence component */
    UR_ERR_MISMATCH = -4,   /* part disagrees with earlier parts (type, lengths, checksum) */
    UR_ERR_LIMIT = -5,      /* beyond the limits above or the caller's buffer */
    UR_ERR_MESSAGE = -6,    /* reassembled message fails its CRC32 */
    UR_ERR_TYPE = -7,       /* complete, but not a PSBT (crypto-psbt / psbt) holding a CBOR byte string */
};

typedef struct {
    uint64_t s[4];
} ur_rng_t;

/* Building blocks, exposed for tests */
uint32_t ur_crc32(const uint8_t *p, size_t n);
void ur_rng_seed(ur_rng_t *r, const uint8_t *seed, size_t n); /* SHA-256 of seed, big-endian words */
uint64_t ur_rng_next(ur_rng_t *r);
double ur_rng_next_double(ur_rng_t *r);
uint64_t ur_rng_next_int(ur_rng_t *r, uint64_t low, uint64_t high);
/* Minimal-style Bytewords (two letters per byte) with the trailing CRC32 checked and removed */
int ur_bytewords_decode(const char *s, size_t n, uint8_t *out, size_t cap);
/* Sampler over weights w[0..n-1] (Vose's alias method as in the reference implementation). w may be probs */
void ur_sampler_init(const double *w, size_t n, double *probs, int16_t *aliases);
int ur_sampler_next(const double *probs, const int16_t *aliases, size_t n, ur_rng_t *r);
size_t ur_choose_degree(size_t seq_len, ur_rng_t *r);
void ur_shuffle(uint16_t *items, size_t n, ur_rng_t *r);
/* Fragment indexes mixed into part seq_num, as a bitset of seq_len bits; returns the count */
size_t ur_choose_fragments(uint32_t seq_num, size_t seq_len, uint32_t checksum, uint8_t *bits);

/* Decoder. work / work_cap hold the reassembled message; type is the lowercase UR type once known */
void ur_decoder_reset(uint8_t *work, size_t work_cap);
/* Feeds one part (modified in place: lowercased). Returns the message length once complete, 0 while
 * more parts are needed, or a negative UR_ERR_* for a rejected part (the decoder keeps its state) */
long ur_decoder_receive(char *s, size_t n);
const char *ur_decoder_type(void);
const uint8_t *ur_decoder_message(void);
/* The payload of a message that is exactly one CBOR byte string; returns 0 otherwise */
int ur_cbor_bytes(const uint8_t *m, size_t n, const uint8_t **data, size_t *len);
/* Parts expected (0 until the first multipart part) and distinct fragments recovered so far */
void ur_decoder_progress(unsigned *expected, unsigned *received);

#endif
