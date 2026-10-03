#ifndef CORE_WIPE_H
#define CORE_WIPE_H

#include <stddef.h>

/* 関数末尾の memset は dead store として消されうるので、秘密値の消去は volatile 経由で書く */
static inline void wipe(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}

#endif
