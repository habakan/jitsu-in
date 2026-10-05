/* Feeds arbitrary bytes to the UR decoder, one part per line, the way an animated QR arrives.
 * A camera sees whatever is put in front of it, so every part is untrusted. */
#include <stdint.h>
#include <string.h>
#include "psbt_parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char *in = parser_input();
    unsigned cap = parser_input_cap();

    parser_ur_reset();
    while (size) {
        const uint8_t *nl = memchr(data, '\n', size);
        size_t n = nl ? (size_t)(nl - data) : size;
        size_t step = nl ? n + 1 : n;
        if (n > cap) n = cap;
        memcpy(in, data, n);
        int rc = parser_ur_receive((unsigned)n);
        if (rc > 0) {
            /* Complete: the PSBT is in the input buffer, so parse it like a host would */
            if ((unsigned)rc > cap) __builtin_trap();
            parser_parse((unsigned)rc, 0x73c5da0au);
            parser_ur_reset();
        }
        data += step;
        size -= step;
    }
    return 0;
}
