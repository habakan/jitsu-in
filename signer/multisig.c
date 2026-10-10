#include "multisig.h"
#include <string.h>
#include "bip32.h"
#include "hash.h"

#define H 0x80000000u

static const char B32[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

typedef struct {
    const char *s;
    size_t n, i;
} cur_t;

static int eat(cur_t *c, const char *lit) {
    size_t k = strlen(lit);
    if (c->n - c->i < k || memcmp(c->s + c->i, lit, k)) return 0;
    c->i += k;
    return 1;
}

/* Decimal below 2^31, without leading zeros */
static int number(cur_t *c, uint32_t *v) {
    size_t start = c->i;
    uint64_t x = 0;
    while (c->i < c->n && c->s[c->i] >= '0' && c->s[c->i] <= '9') {
        x = x * 10 + (uint64_t)(c->s[c->i++] - '0');
        if (x >= H) return 0;
    }
    *v = (uint32_t)x;
    return c->i > start && (c->i - start == 1 || c->s[start] != '0');
}

static int hex_fp(cur_t *c, uint32_t *fp) {
    *fp = 0;
    for (int k = 0; k < 8; k++, c->i++) {
        char ch = c->i < c->n ? c->s[c->i] : 0;
        int d = ch >= '0' && ch <= '9'   ? ch - '0'
                : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10
                : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10
                                         : -1;
        if (d < 0) return 0;
        *fp = *fp << 4 | (uint32_t)d;
    }
    return 1;
}

/* /a'/b'/... with h, H or ' marking each step, every one of them hardened */
static int origin(cur_t *c, ms_key_t *k) {
    k->depth = 0;
    while (eat(c, "/")) {
        if (k->depth == MS_MAX_DEPTH || !number(c, &k->path[k->depth])) return 0;
        if (!eat(c, "h") && !eat(c, "H") && !eat(c, "'")) return 0;
        k->path[k->depth++] |= H;
    }
    return k->depth > 0;
}

static uint32_t be32(const uint8_t *b) {
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}

/* The xpub has to sit where its origin says: same depth, same last step. SLIP-132's Zpub / Vpub name the same
 * key as xpub / tpub, and SeedSigner and Krux show them */
static int xpub(cur_t *c, int testnet, ms_key_t *k) {
    size_t start = c->i;
    uint32_t v;
    secp256k1_pubkey pk;
    while (c->i < c->n && ((c->s[c->i] >= '0' && c->s[c->i] <= '9') || (c->s[c->i] >= 'A' && c->s[c->i] <= 'Z') ||
                           (c->s[c->i] >= 'a' && c->s[c->i] <= 'z')))
        c->i++;
    if (!base58check_decode(c->s + start, c->i - start, k->ser, sizeof(k->ser))) return 0;
    v = be32(k->ser);
    if (testnet ? v != 0x043587cfu && v != 0x02575483u : v != 0x0488b21eu && v != 0x02aa7ed3u) return 0;
    return k->ser[4] == k->depth && be32(k->ser + 9) == k->path[k->depth - 1] &&
           secp256k1_ec_pubkey_parse(secp256k1_context_static, &pk, k->ser + 45, 33);
}

/* [fp/a'/b'/...]xpub, then its children: <0;1>, ** as BSMS writes it, or 0 with change on 1 by convention */
static int key_expr(cur_t *c, int testnet, ms_key_t *k) {
    return eat(c, "[") && hex_fp(c, &k->fingerprint) && origin(c, k) && eat(c, "]") && xpub(c, testnet, k) &&
           (eat(c, "/<0;1>/*") || eat(c, "/**") || eat(c, "/0/*"));
}

static uint64_t desc_polymod(uint64_t c, unsigned v) {
    uint64_t c0 = c >> 35;
    c = ((c & 0x7ffffffffull) << 5) ^ v;
    if (c0 & 1) c ^= 0xf5dee51989ull;
    if (c0 & 2) c ^= 0xa9fdca3312ull;
    if (c0 & 4) c ^= 0x1bab10e32dull;
    if (c0 & 8) c ^= 0x3706b1677aull;
    if (c0 & 16) c ^= 0x644d626ffdull;
    return c;
}

/* BIP380's descriptor checksum */
static int desc_checksum(const char *s, size_t n, char out[9]) {
    static const char IN[] =
        "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    uint64_t c = 1;
    unsigned cls = 0, count = 0;
    for (size_t i = 0; i < n; i++) {
        const char *p = s[i] ? strchr(IN, s[i]) : NULL;
        if (!p) return 0;
        c = desc_polymod(c, (unsigned)(p - IN) & 31);
        cls = cls * 3 + (unsigned)(p - IN) / 32;
        if (++count == 3) c = desc_polymod(c, cls), cls = count = 0;
    }
    if (count) c = desc_polymod(c, cls);
    for (int j = 0; j < 8; j++) c = desc_polymod(c, 0);
    c ^= 1;
    for (int j = 0; j < 8; j++) out[j] = B32[(c >> (5 * (7 - j))) & 31];
    out[8] = 0;
    return 1;
}

/* wsh(sortedmulti(k,KEY,...)) and, if there is one, a checksum that has to hold */
static int descriptor(cur_t *c, int testnet, ms_wallet_t *w) {
    size_t start = c->i;
    uint32_t k;
    char sum[9];
    if (!eat(c, "wsh(sortedmulti(") || !number(c, &k)) return 0;
    for (w->n = 0; eat(c, ",");)
        if (w->n == MS_MAX_KEYS || !key_expr(c, testnet, &w->keys[w->n++])) return 0;
    if (!eat(c, "))") || k < 1 || k > w->n) return 0;
    w->threshold = (uint8_t)k;
    if (!eat(c, "#")) return 1;
    if (!desc_checksum(c->s + start, c->i - 1 - start, sum) || c->n - c->i < 8 || memcmp(c->s + c->i, sum, 8)) return 0;
    c->i += 8;
    return 1;
}

/* The next line, without its line ending or the spaces around it */
static int line(cur_t *c, cur_t *l) {
    size_t a, b;
    if (c->i >= c->n) return 0;
    a = c->i;
    while (c->i < c->n && c->s[c->i] != '\n') c->i++;
    b = c->i;
    if (c->i < c->n) c->i++;
    while (a < b && (c->s[a] == ' ' || c->s[a] == '\t')) a++;
    while (b > a && (c->s[b - 1] == ' ' || c->s[b - 1] == '\t' || c->s[b - 1] == '\r')) b--;
    l->s = c->s + a, l->n = b - a, l->i = 0;
    return 1;
}

static int label(cur_t *l, const char *name) {
    size_t k = strlen(name);
    if (l->n < k + 1 || l->s[k] != ':') return 0;
    for (size_t i = 0; i < k; i++)
        if ((l->s[i] | 0x20) != name[i]) return 0;
    for (l->i = k + 1; l->i < l->n && l->s[l->i] == ' ';) l->i++;
    return 1;
}

/* BIP129: the header, the descriptor, the path restrictions and the first receive address */
static int bsms(cur_t *c, int testnet, ms_wallet_t *w, char address[ADDRESS_MAX]) {
    cur_t l;
    if (!line(c, &l) || !eat(&l, "BSMS 1.0") || l.i != l.n) return 0;
    if (!line(c, &l) || !descriptor(&l, testnet, w) || l.i != l.n) return 0;
    if (!line(c, &l) || (!eat(&l, "/0/*,/1/*") && !eat(&l, "No path restrictions")) || l.i != l.n) return 0;
    if (!line(c, &l) || l.n == 0 || l.n >= ADDRESS_MAX) return 0;
    for (size_t i = 0; i < l.n; i++) address[i] = l.s[i] >= 'A' && l.s[i] <= 'Z' ? (char)(l.s[i] | 0x20) : l.s[i];
    address[l.n] = 0;
    while (line(c, &l))
        if (l.n) return 0;
    return 1;
}

/* Coldcard's setup file, which Sparrow, BlueWallet and Nunchuk also write: Name, Policy: M of N, Derivation
 * (for the keys after it), Format: P2WSH, then FINGERPRINT: xpub lines. # starts a comment */
static int setup_file(cur_t *c, int testnet, ms_wallet_t *w) {
    cur_t l;
    ms_key_t at = {0};
    uint32_t m = 0, n = 0;
    int p2wsh = 0;
    w->n = 0;
    while (line(c, &l)) {
        if (!l.n || l.s[0] == '#' || label(&l, "name")) continue;
        if (label(&l, "policy")) {
            if (!number(&l, &m) || (!eat(&l, " of ") && !eat(&l, "/")) || !number(&l, &n) || l.i != l.n) return 0;
        } else if (label(&l, "derivation")) {
            if (!eat(&l, "m") || !origin(&l, &at) || l.i != l.n) return 0;
        } else if (label(&l, "format")) {
            if (l.n - l.i != 5 || memcmp(l.s + l.i, "P2WSH", 5)) return 0;
            p2wsh = 1;
        } else {
            ms_key_t *k = &w->keys[w->n];
            if (w->n == MS_MAX_KEYS || !at.depth || !hex_fp(&l, &k->fingerprint) || !eat(&l, ":")) return 0;
            while (eat(&l, " "));
            k->depth = at.depth;
            memcpy(k->path, at.path, sizeof(at.path));
            if (!xpub(&l, testnet, k) || l.i != l.n) return 0;
            w->n++;
        }
    }
    w->threshold = (uint8_t)m;
    return p2wsh && n == w->n && m >= 1 && m <= n;
}

int ms_parse(const char *s, size_t len, int testnet, ms_wallet_t *w, char address[ADDRESS_MAX]) {
    cur_t c = {s, len, 0};
    int ok;
    memset(w, 0, sizeof(*w));
    address[0] = 0;
    while (c.n && (s[c.n - 1] == '\n' || s[c.n - 1] == '\r' || s[c.n - 1] == ' ')) c.n--;
    if (c.n >= 8 && !memcmp(s, "BSMS 1.0", 8)) ok = bsms(&c, testnet, w, address);
    else if (c.n >= 4 && !memcmp(s, "wsh(", 4)) ok = descriptor(&c, testnet, w) && c.i == c.n;
    else ok = setup_file(&c, testnet, w);
    for (unsigned i = 0; ok && i < w->n; i++)
        for (unsigned j = 0; j < i; j++) ok &= !!memcmp(w->keys[i].ser + 45, w->keys[j].ser + 45, 33);
    if (!ok) memset(w, 0, sizeof(*w)), address[0] = 0;
    return ok;
}

int ms_wscript(const ms_wallet_t *w, uint32_t chain, uint32_t index, plan_wscript_t *out) {
    uint8_t keys[MS_MAX_KEYS][33], cc[32], mid[33], t[33];
    memset(out, 0, sizeof(*out));
    for (unsigned i = 0; i < w->n; i++) {
        const uint8_t *ser = w->keys[i].ser;
        if (!bip32_pub_child(ser + 45, ser + 13, chain, mid, cc) || !bip32_pub_child(mid, cc, index, keys[i], cc))
            return 0;
        for (unsigned j = i; j > 0 && memcmp(keys[j - 1], keys[j], 33) > 0; j--) {
            memcpy(t, keys[j], 33), memcpy(keys[j], keys[j - 1], 33), memcpy(keys[j - 1], t, 33);
        }
    }
    out->bytes[out->len++] = (uint8_t)(0x50 + w->threshold);
    for (unsigned i = 0; i < w->n; i++) {
        out->bytes[out->len++] = 33;
        memcpy(out->bytes + out->len, keys[i], 33);
        out->len += 33;
    }
    out->bytes[out->len++] = (uint8_t)(0x50 + w->n);
    out->bytes[out->len++] = 0xae;
    return 1;
}

static size_t put(char *out, size_t o, const char *s) {
    size_t n = strlen(s);
    if (o + n >= MS_DESC_MAX) return MS_DESC_MAX;
    memcpy(out + o, s, n);
    out[o + n] = 0;
    return o + n;
}

static void decimal(uint32_t v, char out[11]) {
    char t[10];
    size_t n = 0, o = 0;
    do t[n++] = (char)('0' + v % 10);
    while (v /= 10);
    while (n) out[o++] = t[--n];
    out[o] = 0;
}

size_t ms_descriptor(const ms_wallet_t *w, int testnet, char out[MS_DESC_MAX]) {
    char num[11], x[BASE58CHECK_MAX_OUT];
    uint8_t ser[78];
    size_t o = put(out, 0, "wsh(sortedmulti(");
    decimal(w->threshold, num);
    o = put(out, o, num);
    for (unsigned i = 0; i < w->n; i++) {
        const ms_key_t *k = &w->keys[i];
        o = put(out, o, ",[");
        for (int d = 0; d < 8; d++) num[d] = "0123456789abcdef"[k->fingerprint >> (28 - 4 * d) & 15];
        num[8] = 0;
        o = put(out, o, num);
        for (unsigned d = 0; d < k->depth; d++) {
            decimal(k->path[d] & ~H, num);
            o = put(out, o, "/");
            o = put(out, o, num);
            o = put(out, o, "h");
        }
        o = put(out, o, "]");
        memcpy(ser, k->ser, sizeof(ser));
        memcpy(ser, testnet ? "\x04\x35\x87\xcf" : "\x04\x88\xb2\x1e", 4);
        base58check_data(ser, sizeof(ser), x);
        o = put(out, o, x);
        o = put(out, o, "/<0;1>/*");
    }
    o = put(out, o, "))");
    if (o + 9 >= MS_DESC_MAX || !desc_checksum(out, o, num)) return 0;
    out[o++] = '#';
    memcpy(out + o, num, 9);
    return o + 8;
}
