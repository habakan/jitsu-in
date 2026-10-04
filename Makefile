# Needs clang with the wasm32 target and a wasi-libc sysroot. With Homebrew: llvm / lld / wasi-libc / wasi-runtimes
# WASM_OPT is called explicitly: the clang driver would otherwise run whatever wasm-opt is on PATH,
# which silently changes the output (2.7 KB and a different hash when it is missing)
LLVM    ?= /opt/homebrew/opt/llvm/bin
WASM_OPT ?= wasm-opt
WASI    ?= /opt/homebrew/opt/wasi-libc/share/wasi-sysroot
RTLIB   ?= /opt/homebrew/opt/wasi-runtimes/share/wasi-runtimes/lib/wasm32-unknown-wasip1
SRC     := src/psbt.c src/ur.c src/tx.c src/sha256.c

# The input / output buffers (just over 32 KB each) and the UR decoder need three pages of linear memory. With no memory.grow,
# WAMR's shrunk-memory option trims it down to __heap_base
build/parser.wasm: $(SRC) include/*.h
	mkdir -p build
	$(LLVM)/clang --target=wasm32-wasip1 --sysroot=$(WASI) -nostartfiles -nodefaultlibs -Oz -Wall -Wextra \
	  -Iinclude -Wl,--no-entry -Wl,--gc-sections -Wl,--strip-all -Wl,-z,stack-size=16384 \
	  -Wl,--export=__heap_base -Wl,--export=__data_end -Wl,--initial-memory=196608 -Wl,--max-memory=196608 \
	  --no-wasm-opt -Wl,--keep-section=target_features \
	  -o $@ $(SRC) -lc $(RTLIB)/libclang_rt.builtins.a
	$(WASM_OPT) $@ -Oz -o $@
	shasum -a 256 $@

build/vectors/own_p2wpkh_1in.psbt: tools/gen_vectors.py tests/rpc_psbt.json
	rm -rf build/vectors && uv run -q $< tests/rpc_psbt.json build/vectors

# UR building blocks against the bc-ur reference tests, natively with sanitizers
build/test_ur: tests/test_ur.c tests/ur_ref_vectors.h src/ur.c src/sha256.c include/*.h
	mkdir -p build
	cc -O2 -Wall -Wextra -Iinclude -Itests -fsanitize=address,undefined -o $@ tests/test_ur.c src/ur.c src/sha256.c

# Fuzzing. Needs a clang with libFuzzer (Apple's does not ship it; Homebrew's llvm does).
# The PSBT and the UR parts both come from whoever holds up a QR code, so both are fuzzed.
FUZZ_CC  := $(LLVM)/clang
FUZZ_CFLAGS := -O1 -g -Wall -Wextra -Iinclude -fsanitize=fuzzer,address,undefined \
  -fno-sanitize-recover=all -fuse-ld=lld

build/fuzz_%: tests/fuzz_%.c $(SRC) include/*.h
	mkdir -p build
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $< $(SRC)

# Seeds: the PSBT vectors, and the UR parts from the reference encoder
build/corpus/psbt: build/vectors/own_p2wpkh_1in.psbt
	mkdir -p $@ && for f in build/vectors/*.psbt; do \
	  printf '\x73\xc5\xda\x0a' | cat - $$f > $@/$$(basename $$f); done

build/corpus/ur: tests/ur_vectors.json
	mkdir -p $@ && python3 -c "import json; \
	  v=json.load(open('tests/ur_vectors.json'))['vectors']; \
	  [open('$@/%s_%d' % (x['name'], x['fragment_len']), 'w').write('\n'.join(x['parts'])) for x in v]"

# Run until stopped: make fuzz-psbt / make fuzz-ur
fuzz-%: build/fuzz_% build/corpus/%
	build/fuzz_$* build/corpus/$* -max_len=40000
.PHONY: fuzz-psbt fuzz-ur

# Short deterministic run, for CI
check-fuzz: build/fuzz_psbt build/fuzz_ur build/corpus/psbt build/corpus/ur
	build/fuzz_psbt build/corpus/psbt -runs=200000 -max_len=40000 -print_final_stats=1
	build/fuzz_ur   build/corpus/ur   -runs=200000 -max_len=40000 -print_final_stats=1
.PHONY: check-fuzz

# The JavaScript host. Tests the host itself: hidden offsets, named errors, and that a module
# returning a bad offset is stopped rather than followed
check-hosts: build/parser.wasm build/vectors/own_p2wpkh_1in.psbt
	node hosts/js/test.mjs build/parser.wasm build/vectors
.PHONY: check-hosts

test: build/parser.wasm build/vectors/own_p2wpkh_1in.psbt build/test_ur
	build/test_ur
	uv run -q tools/run_tests.py build/parser.wasm build/vectors tests/rpc_psbt.json tests/ur_vectors.json
	$(MAKE) check-hosts

clean:
	rm -rf build
.PHONY: test clean
