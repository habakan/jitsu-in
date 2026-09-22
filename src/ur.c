/* Uniform Resources decoding (BCR-2020-005), following the Blockchain Commons reference implementation
 * (bc-ur) closely where the result must match bit for bit: the Xoshiro256** seeding, the alias sampler,
 * the shuffle and therefore which fragments each mixed part combines. */

#include "ur.h"
#include <string.h>
#include "reader.h"
#include "sha256.h"

#define BITS_BYTES (UR_MAX_SEQ_LEN / 8)

static const char WORDS[] =
    "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschef"
    "cityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyecho"
    "edgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgift"
    "girlglowgoodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyinto"
    "irisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazy"
    "leaflegsliarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneed"
    "newsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizrace"
    "ramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotask"
    "taxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswall"
    "wandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom";

uint32_t ur_crc32(const uint8_t *p, size_t n) {
    uint32_t c = 0xffffffffu;
    while (n--) {
        c ^= *p++;
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1)));
    }
    return ~c;
}

static uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

void ur_rng_seed(ur_rng_t *r, const uint8_t *seed, size_t n) {
    uint8_t h[32];
    sha256(seed, n, h);
    for (int i = 0; i < 4; i++) {
        r->s[i] = 0;
        for (int k = 0; k < 8; k++) r->s[i] = r->s[i] << 8 | h[8 * i + k];
    }
}

uint64_t ur_rng_next(ur_rng_t *r) {
    uint64_t *s = r->s, result = rotl(s[1] * 5, 7) * 9, t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 45);
    return result;
}

double ur_rng_next_double(ur_rng_t *r) { return (double)ur_rng_next(r) / 18446744073709551616.0; }

uint64_t ur_rng_next_int(ur_rng_t *r, uint64_t low, uint64_t high) {
    return (uint64_t)(ur_rng_next_double(r) * (double)(high - low + 1)) + low;
}

int ur_bytewords_decode(const char *s, size_t n, uint8_t *out, size_t cap) {
    static int16_t table[26 * 26];
    static int ready;
    size_t len = n / 2;

    if (!ready) {
        for (int i = 0; i < 26 * 26; i++) table[i] = -1;
        for (int i = 0; i < 256; i++) table[(WORDS[4 * i + 3] - 'a') * 26 + (WORDS[4 * i] - 'a')] = (int16_t)i;
        ready = 1;
    }
    if (n % 2 || len < 5 || len > cap) return -1;
    /* out may alias s: byte i is written only after letters 2i and 2i+1 have been read */
    for (size_t i = 0; i < len; i++) {
        int x = s[2 * i] - 'a', y = s[2 * i + 1] - 'a';
        if (x < 0 || x >= 26 || y < 0 || y >= 26 || table[y * 26 + x] < 0) return -1;
        out[i] = (uint8_t)table[y * 26 + x];
    }
    len -= 4;
    if (ur_crc32(out, len) != ((uint32_t)out[len] << 24 | (uint32_t)out[len + 1] << 16 |
                               (uint32_t)out[len + 2] << 8 | out[len + 3]))
        return -1;
    return (int)len;
}

/* w may alias probs: each weight is read before its slot is written, and a slot that has been finalized
 * (popped from the small stack) is never read again. The small and large stacks share one array, growing
 * from opposite ends, since every index sits in exactly one of them */
void ur_sampler_init(const double *w, size_t n, double *probs, int16_t *aliases) {
    static int16_t stack[UR_MAX_SEQ_LEN];
    size_t ns = 0, nl = 0;
    double sum = 0;

    for (size_t i = 0; i < n; i++) sum += w[i];
    for (size_t i = 0; i < n; i++) probs[i] = w[i] * (double)n / sum;
    /* reversed index order, as in the reference */
    for (int i = (int)n - 1; i >= 0; i--) {
        if (probs[i] < 1)
            stack[ns++] = (int16_t)i;
        else
            stack[n - 1 - nl++] = (int16_t)i;
    }
    for (size_t i = 0; i < n; i++) aliases[i] = 0;
    while (ns && nl) {
        int a = stack[--ns], g = stack[n - nl--];
        aliases[a] = (int16_t)g;
        probs[g] += probs[a] - 1;
        if (probs[g] < 1)
            stack[ns++] = (int16_t)g;
        else
            stack[n - 1 - nl++] = (int16_t)g;
    }
    while (nl) probs[stack[n - nl--]] = 1;
    while (ns) probs[stack[--ns]] = 1;
}

int ur_sampler_next(const double *probs, const int16_t *aliases, size_t n, ur_rng_t *r) {
    double r1 = ur_rng_next_double(r), r2 = ur_rng_next_double(r);
    int i = (int)((double)n * r1);
    return r2 < probs[i] ? i : aliases[i];
}

size_t ur_choose_degree(size_t seq_len, ur_rng_t *r) {
    static double probs[UR_MAX_SEQ_LEN];
    static int16_t aliases[UR_MAX_SEQ_LEN];
    for (size_t i = 1; i <= seq_len; i++) probs[i - 1] = 1.0 / (double)i;
    ur_sampler_init(probs, seq_len, probs, aliases);
    return (size_t)ur_sampler_next(probs, aliases, seq_len, r) + 1;
}

/* The reference moves the chosen item from a "remaining" list to the result. Here the result grows at the
 * front of items and the remaining items stay behind it in their original order */
void ur_shuffle(uint16_t *items, size_t n, ur_rng_t *r) {
    for (size_t k = 0; k < n; k++) {
        size_t i = (size_t)ur_rng_next_int(r, 0, n - k - 1);
        uint16_t item = items[k + i];
        memmove(items + k + 1, items + k, i * sizeof(uint16_t));
        items[k] = item;
    }
}

size_t ur_choose_fragments(uint32_t seq_num, size_t seq_len, uint32_t checksum, uint8_t *bits) {
    static uint16_t idx[UR_MAX_SEQ_LEN];
    uint8_t seed[8] = {(uint8_t)(seq_num >> 24), (uint8_t)(seq_num >> 16), (uint8_t)(seq_num >> 8), (uint8_t)seq_num,
                       (uint8_t)(checksum >> 24), (uint8_t)(checksum >> 16), (uint8_t)(checksum >> 8), (uint8_t)checksum};
    ur_rng_t r;
    size_t degree;

    memset(bits, 0, (seq_len + 7) / 8);
    if (seq_num <= seq_len) {
        bits[(seq_num - 1) / 8] |= (uint8_t)(1u << ((seq_num - 1) % 8));
        return 1;
    }
    ur_rng_seed(&r, seed, sizeof(seed));
    degree = ur_choose_degree(seq_len, &r);
    for (size_t i = 0; i < seq_len; i++) idx[i] = (uint16_t)i;
    ur_shuffle(idx, seq_len, &r);
    for (size_t i = 0; i < degree; i++) bits[idx[i] / 8] |= (uint8_t)(1u << (idx[i] % 8));
    return degree;
}

/* ---- decoder ---- */

typedef struct {
    uint8_t bits[BITS_BYTES];
    uint16_t count; /* 0 marks a free slot */
} mixed_t;

static struct {
    uint8_t *work;
    size_t work_cap;
    char type[32];
    int multipart;
    uint32_t seq_len, message_len, checksum;
    size_t frag_len, slots;
    uint8_t have[BITS_BYTES];
    unsigned received, evict;
    long done;
    mixed_t mixed[UR_MAX_MIXED];
    uint8_t pool[UR_MIXED_POOL];
    uint16_t stack[UR_MAX_SEQ_LEN];
    size_t sp;
} d;

static int bit(const uint8_t *b, size_t i) { return b[i / 8] >> (i % 8) & 1; }

static void xor_into(uint8_t *dst, const uint8_t *src, size_t n) {
    while (n--) *dst++ ^= *src++;
}

static uint8_t *frag(size_t i) { return d.work + i * d.frag_len; }
static uint8_t *slot_data(size_t s) { return d.pool + s * d.frag_len; }

static size_t only_index(const uint8_t *bits) {
    for (size_t i = 0; i < d.seq_len; i++)
        if (bit(bits, i)) return i;
    return 0;
}

/* Records fragment i and queues it for reducing the kept mixed parts */
static void add_simple(size_t i, const uint8_t *data) {
    if (bit(d.have, i)) return;
    memcpy(frag(i), data, d.frag_len);
    d.have[i / 8] |= (uint8_t)(1u << (i % 8));
    d.received++;
    d.stack[d.sp++] = (uint16_t)i;
}

/* Removes every known fragment from the kept mixed parts; parts reduced to one fragment become simple */
static void drain(void) {
    while (d.sp) {
        size_t i = d.stack[--d.sp];
        for (size_t s = 0; s < d.slots; s++) {
            mixed_t *m = &d.mixed[s];
            if (!m->count || !bit(m->bits, i)) continue;
            xor_into(slot_data(s), frag(i), d.frag_len);
            m->bits[i / 8] &= (uint8_t)~(1u << (i % 8));
            if (--m->count == 1) {
                m->count = 0;
                add_simple(only_index(m->bits), slot_data(s));
            }
        }
    }
}

static int is_strict_subset(const uint8_t *a, const uint8_t *b) {
    int equal = 1;
    for (size_t k = 0; k < BITS_BYTES; k++) {
        if (a[k] & ~b[k]) return 0;
        if (a[k] != b[k]) equal = 0;
    }
    return !equal;
}

static void add_mixed(uint8_t *bits, size_t count, uint8_t *data) {
    for (size_t i = 0; i < d.seq_len && count > 1; i++) {
        if (!bit(bits, i) || !bit(d.have, i)) continue;
        xor_into(data, frag(i), d.frag_len);
        bits[i / 8] &= (uint8_t)~(1u << (i % 8));
        count--;
    }
    for (size_t s = 0; s < d.slots && count > 1; s++) {
        mixed_t *m = &d.mixed[s];
        if (!m->count) continue;
        if (!memcmp(m->bits, bits, BITS_BYTES)) return; /* already kept */
        if (is_strict_subset(m->bits, bits)) {
            xor_into(data, slot_data(s), d.frag_len);
            for (size_t k = 0; k < BITS_BYTES; k++) bits[k] &= (uint8_t)~m->bits[k];
            count -= m->count;
        }
    }
    if (count == 1) {
        add_simple(only_index(bits), data);
        return;
    }
    if (count == 0 || d.slots == 0) return;
    /* keep it, overwriting the oldest kept part when full */
    size_t s = d.slots;
    for (size_t k = 0; k < d.slots; k++)
        if (!d.mixed[k].count) {
            s = k;
            break;
        }
    if (s == d.slots) s = d.evict++ % d.slots;
    memcpy(d.mixed[s].bits, bits, BITS_BYTES);
    memcpy(slot_data(s), data, d.frag_len);
    d.mixed[s].count = (uint16_t)count;
    /* earlier parts that contain this one can drop its fragments too */
    for (size_t k = 0; k < d.slots; k++) {
        mixed_t *m = &d.mixed[k];
        if (k == s || !m->count || !is_strict_subset(bits, m->bits)) continue;
        xor_into(slot_data(k), data, d.frag_len);
        for (size_t b = 0; b < BITS_BYTES; b++) m->bits[b] &= (uint8_t)~bits[b];
        m->count = (uint16_t)(m->count - count);
        if (m->count == 1) {
            m->count = 0;
            add_simple(only_index(m->bits), slot_data(k));
        }
    }
}

void ur_decoder_reset(uint8_t *work, size_t work_cap) {
    memset(&d, 0, sizeof(d));
    d.work = work;
    d.work_cap = work_cap;
}

const char *ur_decoder_type(void) { return d.type; }
const uint8_t *ur_decoder_message(void) { return d.work; }

void ur_decoder_progress(unsigned *expected, unsigned *received) {
    *expected = d.multipart ? d.seq_len : 0;
    *received = d.received;
}

static int parse_uint(const char *s, size_t n, uint32_t *out) {
    uint64_t v = 0;
    if (n == 0 || n > 10) return 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    if (v > 0xffffffffu) return 0;
    *out = (uint32_t)v;
    return 1;
}

/* CBOR head of the given major type; returns its argument (big-endian, 1..8 bytes after the head) */
static uint64_t cbor_uint(rd_t *r, int major) {
    uint64_t head = rd_le(r, 1), v = head & 31;
    int extra = v == 24 ? 1 : v == 25 ? 2 : v == 26 ? 4 : v == 27 ? 8 : 0;
    if ((int)(head >> 5) != major || v > 27) r->err = 1;
    if (extra) v = 0;
    for (int k = 0; k < extra; k++) v = v << 8 | rd_le(r, 1);
    return r->err ? 0 : v;
}

int ur_cbor_bytes(const uint8_t *m, size_t n, const uint8_t **data, size_t *len) {
    rd_t r = {m, n, 0, 0};
    uint64_t v = cbor_uint(&r, 2);
    if (r.err || v != n - r.pos) return 0;
    *data = m + r.pos;
    *len = (size_t)v;
    return 1;
}

long ur_decoder_receive(char *s, size_t n) {
    uint8_t *body = (uint8_t *)s, bits[BITS_BYTES];
    char type[sizeof(d.type)];
    size_t type_len = 0, rest, seq_end;
    uint32_t seq_num, seq_len;
    int len;

    if (d.done) return d.done;
    for (size_t i = 0; i < n; i++)
        if (s[i] >= 'A' && s[i] <= 'Z') s[i] = (char)(s[i] - 'A' + 'a');
    if (n < 4 || memcmp(s, "ur:", 3)) return UR_ERR_SCHEME;
    while (3 + type_len < n && s[3 + type_len] != '/') {
        char c = s[3 + type_len];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return UR_ERR_SCHEME;
        type_len++;
    }
    if (type_len == 0 || type_len >= sizeof(type) || 3 + type_len == n) return UR_ERR_SCHEME;
    memcpy(type, s + 3, type_len); /* before the bytewords are decoded over s */
    type[type_len] = 0;
    if (d.type[0] && strcmp(d.type, type)) return UR_ERR_MISMATCH;
    rest = 3 + type_len + 1;

    /* single-part: ur:<type>/<bytewords> */
    for (seq_end = rest; seq_end < n && s[seq_end] != '/'; seq_end++) {
    }
    if (seq_end == n) {
        if ((len = ur_bytewords_decode(s + rest, n - rest, body, n)) < 0) return UR_ERR_BYTEWORDS;
        if ((size_t)len > d.work_cap) return UR_ERR_LIMIT;
        memcpy(d.type, type, sizeof(type));
        memcpy(d.work, body, (size_t)len);
        return d.done = len;
    }

    /* multipart: ur:<type>/<seq>-<len>/<bytewords of [seq_num, seq_len, message_len, checksum, fragment]> */
    {
        const char *dash = memchr(s + rest, '-', seq_end - rest);
        uint32_t c_seq_num, c_seq_len, message_len, checksum;
        size_t frag_len;
        rd_t r;
        const uint8_t *data;

        if (!dash || !parse_uint(s + rest, (size_t)(dash - (s + rest)), &c_seq_num) ||
            !parse_uint(dash + 1, (size_t)(s + seq_end - dash - 1), &c_seq_len) || !c_seq_num || !c_seq_len)
            return UR_ERR_PART;
        if (memchr(s + seq_end + 1, '/', n - seq_end - 1)) return UR_ERR_PART;
        if ((len = ur_bytewords_decode(s + seq_end + 1, n - seq_end - 1, body, n)) < 0) return UR_ERR_BYTEWORDS;
        r = (rd_t){body, (size_t)len, 0, 0};
        if (rd_le(&r, 1) != 0x85) return UR_ERR_PART;
        uint64_t f[4];
        for (int k = 0; k < 4; k++) f[k] = cbor_uint(&r, 0);
        frag_len = (size_t)cbor_uint(&r, 2);
        data = rd_take(&r, frag_len);
        if (r.err || r.pos != r.n || f[0] > 0xffffffffu || f[1] > 0xffffffffu || f[2] > 0xffffffffu ||
            f[3] > 0xffffffffu)
            return UR_ERR_PART;
        seq_num = (uint32_t)f[0], seq_len = (uint32_t)f[1], message_len = (uint32_t)f[2], checksum = (uint32_t)f[3];
        if (seq_num != c_seq_num || seq_len != c_seq_len || !seq_num || !frag_len) return UR_ERR_PART;
        /* the encoder splits into ceil(message_len / frag_len) fragments */
        if (seq_len > UR_MAX_SEQ_LEN || (size_t)seq_len * frag_len > d.work_cap) return UR_ERR_LIMIT;
        if (!message_len || (message_len + frag_len - 1) / frag_len != seq_len) return UR_ERR_PART;
        if (!d.multipart) {
            memcpy(d.type, type, sizeof(type));
            d.multipart = 1;
            d.seq_len = seq_len, d.message_len = message_len, d.checksum = checksum, d.frag_len = frag_len;
            d.slots = UR_MIXED_POOL / frag_len < UR_MAX_MIXED ? UR_MIXED_POOL / frag_len : UR_MAX_MIXED;
        } else if (seq_len != d.seq_len || message_len != d.message_len || checksum != d.checksum ||
                   frag_len != d.frag_len) {
            return UR_ERR_MISMATCH;
        }
        memmove(body, data, frag_len);
        memset(bits, 0, sizeof(bits)); /* set comparisons look at all BITS_BYTES */
        size_t count = ur_choose_fragments(seq_num, seq_len, checksum, bits);
        if (count == 1)
            add_simple(only_index(bits), body);
        else
            add_mixed(bits, count, body);
        drain();
        if (d.received < d.seq_len) return 0;
        if (ur_crc32(d.work, d.message_len) != d.checksum) {
            uint8_t *work = d.work;
            size_t cap = d.work_cap;
            ur_decoder_reset(work, cap);
            return UR_ERR_MESSAGE;
        }
        return d.done = d.message_len;
    }
}
