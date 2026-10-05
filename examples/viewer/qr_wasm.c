/* For the browser: reads QRs with the same quirc the device runs, the fixed-point fork */
#include <stddef.h>
#include <stdint.h>
#include "quirc.h"

/* quirc calls malloc, but pulling in wasi-libc would add imports. This allocator only ever grows and
 * resets to the start on each qr_init; freeing does nothing */
static uint8_t arena[1u << 21];
static size_t used;

void *malloc(size_t n) {
    size_t p = (used + 7) & ~(size_t)7;
    if (p + n > sizeof(arena)) return NULL;
    used = p + n;
    return arena + p;
}
void *calloc(size_t n, size_t m) {
    uint8_t *p = malloc(n * m);
    if (p)
        for (size_t i = 0; i < n * m; i++) p[i] = 0;
    return p;
}
void free(void *p) {
    (void)p;
}

static struct quirc *q;
static struct quirc_data data;

__attribute__((export_name("qr_init"))) int qr_init(int w, int h) {
    used = 0; /* back to the start, which invalidates q, so it is rebuilt */
    q = quirc_new();
    return q && quirc_resize(q, w, h) >= 0;
}
/* Write w*h bytes of 8-bit greyscale here, then call qr_decode */
__attribute__((export_name("qr_input"))) uint8_t *qr_input(void) {
    return quirc_begin(q, NULL, NULL);
}
__attribute__((export_name("qr_output"))) uint8_t *qr_output(void) {
    return data.payload;
}

/* The last QR's size in pixels and in modules, for working out why one will not read */
static int last_px, last_cells, last_err;

__attribute__((export_name("qr_last_px"))) int qr_last_px(void) {
    return last_px;
}
__attribute__((export_name("qr_last_cells"))) int qr_last_cells(void) {
    return last_cells;
}
__attribute__((export_name("qr_last_err"))) int qr_last_err(void) {
    return last_err;
}

/* The length of the first QR read: 0 if none was found, negative if one was found but did not decode */
__attribute__((export_name("qr_decode"))) int qr_decode(void) {
    quirc_end(q);
    int n = quirc_count(q);
    last_px = last_cells = last_err = 0;
    for (int i = 0; i < n; i++) {
        struct quirc_code code;
        quirc_extract(q, i, &code);
        int dx = code.corners[1].x - code.corners[0].x, dy = code.corners[1].y - code.corners[0].y;
        int d2 = dx * dx + dy * dy, px = 1;
        while (px * px < d2) px++; /* an integer square root, so libm is not pulled in */
        last_px = px;
        last_cells = code.size;
        last_err = quirc_decode(&code, &data);
        if (!last_err) return data.payload_len;
    }
    return n ? -1 : 0;
}
