/* The authoritative layout of everything a host has to decode out of signer.wasm's memory.
 * Printing it from C is the only way these numbers cannot drift from the structs they describe;
 * tools/check_layout.py compares this against what the host libraries assume. */
#include <stddef.h>
#include <stdio.h>
#include "core.h"

#define F(type, field) printf("  \"%s\": %zu,\n", #field, offsetof(type, field))

int main(void) {
    printf("{\n");
    printf(" \"plan_t\": {\n");
    printf("  \"size\": %zu,\n", sizeof(plan_t));
    F(plan_t, magic);
    F(plan_t, version);
    F(plan_t, tx_version);
    F(plan_t, locktime);
    F(plan_t, n_inputs);
    F(plan_t, n_outputs);
    F(plan_t, inputs);
    F(plan_t, outputs);
    printf("  \"input_size\": %zu,\n", sizeof(plan_input_t));
    printf("  \"output_size\": %zu\n },\n", sizeof(plan_output_t));

    printf(" \"core_review_t\": {\n");
    printf("  \"size\": %zu,\n", sizeof(core_review_t));
    F(core_review_t, total_in);
    F(core_review_t, total_out);
    F(core_review_t, fee);
    F(core_review_t, owner);
    F(core_review_t, will_sign);
    F(core_review_t, n_sign);
    printf("  \"_end\": 0\n },\n");

    printf(" \"core_display_t\": {\n");
    printf("  \"size\": %zu,\n", sizeof(core_display_t));
    F(core_display_t, fee);
    F(core_display_t, spend);
    F(core_display_t, n_outputs);
    F(core_display_t, outputs);
    printf("  \"output_size\": %zu,\n", sizeof(core_display_output_t));
    printf("  \"output_amount\": %zu,\n", offsetof(core_display_output_t, amount));
    printf("  \"output_owner\": %zu,\n", offsetof(core_display_output_t, owner));
    printf("  \"output_text_kind\": %zu,\n", offsetof(core_display_output_t, text_kind));
    printf("  \"output_text\": %zu,\n", offsetof(core_display_output_t, text));
    printf("  \"output_text_cap\": %d\n },\n", 2 * PLAN_MAX_SPK + 1);

    printf(" \"plan_sig_t\": {\n");
    printf("  \"size\": %zu,\n", sizeof(plan_sig_t));
    F(plan_sig_t, input);
    F(plan_sig_t, pubkey);
    F(plan_sig_t, sig_len);
    F(plan_sig_t, sig);
    printf("  \"_end\": 0\n },\n");

    printf(" \"limits\": {\n");
    printf("  \"max_inputs\": %d,\n", PLAN_MAX_INPUTS);
    printf("  \"max_outputs\": %d,\n", PLAN_MAX_OUTPUTS);
    printf("  \"max_spk\": %d,\n", PLAN_MAX_SPK);
    printf("  \"max_depth\": %d,\n", PLAN_MAX_DEPTH);
    printf("  \"xpub_max\": %d,\n", CORE_XPUB_MAX);
    printf("  \"desc_max\": %d\n },\n", CORE_DESC_MAX);

    printf(" \"errors\": {\n");
    printf("  \"FORMAT\": %d, \"NO_SEED\": %d, \"NOT_OURS\": %d, \"NOTHING_TO_SIGN\": %d,\n",
           CORE_ERR_FORMAT, CORE_ERR_NO_SEED, CORE_ERR_NOT_OURS, CORE_ERR_NOTHING_TO_SIGN);
    printf("  \"SIGHASH\": %d, \"SCRIPT\": %d, \"PREVTX_MISSING\": %d, \"PREVTX_MISMATCH\": %d,\n",
           CORE_ERR_SIGHASH, CORE_ERR_SCRIPT, CORE_ERR_PREVTX_MISSING, CORE_ERR_PREVTX_MISMATCH);
    printf("  \"FEE\": %d, \"NOT_REVIEWED\": %d, \"CRYPTO\": %d\n },\n",
           CORE_ERR_FEE, CORE_ERR_NOT_REVIEWED, CORE_ERR_CRYPTO);

    printf(" \"owner\": {\"EXTERNAL\": %d, \"CHANGE\": %d, \"SELF\": %d},\n",
           CORE_OUT_EXTERNAL, CORE_OUT_CHANGE, CORE_OUT_SELF);
    printf(" \"text_kind\": {\"ADDRESS\": %d, \"OP_RETURN\": %d, \"SCRIPT\": %d}\n",
           CORE_TEXT_ADDRESS, CORE_TEXT_OP_RETURN, CORE_TEXT_SCRIPT);
    printf("}\n");
    return 0;
}
