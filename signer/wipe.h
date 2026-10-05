#ifndef CORE_WIPE_H
#define CORE_WIPE_H

#include <stddef.h>

/* A memset at the end of a function can be dropped as a dead store, so secrets are cleared through
 * a volatile pointer instead */
static inline void wipe(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}

#endif
