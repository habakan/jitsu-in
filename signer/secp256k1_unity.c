/* libsecp256k1 as one translation unit, so the linker can drop what signing does not reach.
 * Included by path rather than relatively: where third_party/ sits depends on whether this is built
 * inside this repository or as a submodule of one, and a relative path only works in one of them. */
#include <secp256k1.c>
#include <precomputed_ecmult.c>
#include <precomputed_ecmult_gen.c>
