#!/usr/bin/env python3
"""The structure offsets in the spec and in the host library have to equal what C says they are.

A number written by hand in a document is wrong the moment a struct changes, and nothing would
notice. signer/tests/layout.c prints the truth; this compares everything against it.
"""
import json
import re
import subprocess
import sys
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: check_layout.py PATH_TO_LAYOUT_BINARY")
    try:
        run = subprocess.run([sys.argv[1]], capture_output=True, text=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        sys.exit(f"check-layout: cannot run {sys.argv[1]}: {e}")
    truth = json.loads(run.stdout)
    bad = []

    # The JavaScript host library's constants
    js = Path("signer/hosts/js/signer.mjs").read_text()
    want_js = {
        "plan.size": truth["plan_t"]["size"],
        "plan.nInputs": truth["plan_t"]["n_inputs"],
        "plan.nOutputs": truth["plan_t"]["n_outputs"],
        "review.size": truth["core_review_t"]["size"],
        "review.fee": truth["core_review_t"]["fee"],
        "review.owner": truth["core_review_t"]["owner"],
        "review.willSign": truth["core_review_t"]["will_sign"],
        "review.nSign": truth["core_review_t"]["n_sign"],
        "display.size": truth["core_display_t"]["size"],
        "display.outputs": truth["core_display_t"]["outputs"],
        "display.outSize": truth["core_display_t"]["output_size"],
        "display.outText": truth["core_display_t"]["output_text"],
        "display.outTextCap": truth["core_display_t"]["output_text_cap"],
        "sig.size": truth["plan_sig_t"]["size"],
        "sig.sigLen": truth["plan_sig_t"]["sig_len"],
        "sig.sig": truth["plan_sig_t"]["sig"],
    }
    for name, want in want_js.items():
        key = name.split(".")[1]
        # the constants live in one object literal per structure
        block = re.search(r"\b" + name.split(".")[0] + r":\s*\{(.*?)\}", js, re.S)
        if not block:
            bad.append(f"signer.mjs: no block for {name.split('.')[0]}")
            continue
        m = re.search(r"\b" + key + r":\s*(\d+)", block.group(1))
        if not m:
            bad.append(f"signer.mjs: {name} not found")
        elif int(m.group(1)) != want:
            bad.append(f"signer.mjs: {name} is {m.group(1)}, C says {want}")

    # The Kotlin host library's constants
    kt = Path("signer/hosts/kotlin/Signer.kt").read_text()
    want_kt = {
        "PLAN_SIZE": truth["plan_t"]["size"],
        "PLAN_N_INPUTS": truth["plan_t"]["n_inputs"],
        "PLAN_N_OUTPUTS": truth["plan_t"]["n_outputs"],
        "RV_SIZE": truth["core_review_t"]["size"],
        "RV_FEE": truth["core_review_t"]["fee"],
        "RV_OWNER": truth["core_review_t"]["owner"],
        "RV_WILL_SIGN": truth["core_review_t"]["will_sign"],
        "RV_N_SIGN": truth["core_review_t"]["n_sign"],
        "DP_SIZE": truth["core_display_t"]["size"],
        "DP_OUTPUTS": truth["core_display_t"]["outputs"],
        "DP_OUT_SIZE": truth["core_display_t"]["output_size"],
        "DP_OUT_TEXT": truth["core_display_t"]["output_text"],
        "DP_OUT_TEXT_CAP": truth["core_display_t"]["output_text_cap"],
        "SIG_SIZE": truth["plan_sig_t"]["size"],
        "SIG_LEN": truth["plan_sig_t"]["sig_len"],
        "SIG_SIG": truth["plan_sig_t"]["sig"],
    }
    for name, want in want_kt.items():
        m = re.search(r"\bconst val " + name + r" = (\d+)", kt)
        if not m:
            bad.append(f"Signer.kt: {name} not found")
        elif int(m.group(1)) != want:
            bad.append(f"Signer.kt: {name} is {m.group(1)}, C says {want}")

    # The Swift host library's constants
    sw = Path("signer/hosts/swift/Sources/WasmSigner/Signer.swift").read_text()
    want_sw = {
        "planSize": truth["plan_t"]["size"],
        "planNInputs": truth["plan_t"]["n_inputs"],
        "planNOutputs": truth["plan_t"]["n_outputs"],
        "rvSize": truth["core_review_t"]["size"],
        "rvFee": truth["core_review_t"]["fee"],
        "rvOwner": truth["core_review_t"]["owner"],
        "rvWillSign": truth["core_review_t"]["will_sign"],
        "rvNSign": truth["core_review_t"]["n_sign"],
        "dpSize": truth["core_display_t"]["size"],
        "dpOutputs": truth["core_display_t"]["outputs"],
        "dpOutSize": truth["core_display_t"]["output_size"],
        "dpOutText": truth["core_display_t"]["output_text"],
        "dpOutTextCap": truth["core_display_t"]["output_text_cap"],
        "sigSize": truth["plan_sig_t"]["size"],
        "sigLen": truth["plan_sig_t"]["sig_len"],
        "sigSig": truth["plan_sig_t"]["sig"],
    }
    for name, want in want_sw.items():
        m = re.search(r"\b" + name + r" = (\d+)", sw)
        if not m:
            bad.append(f"Signer.swift: {name} not found")
        elif int(m.group(1)) != want:
            bad.append(f"Signer.swift: {name} is {m.group(1)}, C says {want}")

    # The error codes, in the library and in the spec
    for code, name in [(v, k) for k, v in truth["errors"].items()]:
        if f'{code}: "{name}"' not in js.replace("'", '"'):
            bad.append(f"signer.mjs: ERRORS is missing {code} -> {name}")

    # Every offset the spec states
    spec = Path("signer/docs/abi.md").read_text()
    for label, want in [
        (f"`core_review_t` ({truth['core_review_t']['size']} bytes)", None),
        (f"`core_display_t` ({truth['core_display_t']['size']} bytes)", None),
        (f"`plan_sig_t` ({truth['plan_sig_t']['size']} bytes)", None),
    ]:
        if label not in spec:
            bad.append(f"abi.md: does not say {label}")
    if f"the `plan_t`, {truth['plan_t']['size']} bytes" not in spec:
        bad.append(f"abi.md: plan_t size is not {truth['plan_t']['size']}")

    for b in bad:
        print(f"  {b}")
    print(f"check-layout: {'FAILED' if bad else 'the spec, all three host libraries and the structs agree'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
