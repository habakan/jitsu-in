# Two WebAssembly modules and the host libraries that drive them. The parser has no keys; the signer
# has nothing else. docs/module-abi.md is the convention both follow.
#
#   make              build both modules
#   make test         everything: vectors, every host library, the layout, the shape of the output
#   make deps         fetch libsecp256k1 at its pinned commit (the signer needs it)
LLVM     ?= /opt/homebrew/opt/llvm/bin
WASI     ?= /opt/homebrew/opt/wasi-libc/share/wasi-sysroot
RTLIB    ?= /opt/homebrew/opt/wasi-runtimes/share/wasi-runtimes/lib/wasm32-unknown-wasip1
WASM_OPT ?= wasm-opt
TOOLS    := LLVM=$(LLVM) WASI=$(WASI) RTLIB=$(RTLIB) WASM_OPT=$(WASM_OPT)

# Lime1: WebAssembly 1.0 plus seven phase-5 features, defined in WebAssembly/tool-conventions/Lime.md
# and promised not to change. Passing it to the linker makes it a gate: if a dependency ever starts
# using SIMD or threads, the link fails instead of the module quietly requiring more of a runtime.
LIME1 := mutable-globals,multivalue,sign-ext,nontrapping-fptoint,bulk-memory-opt,extended-const,call-indirect-overlong
LIME_FLAGS := -mcpu=lime1 -Xlinker --features=$(LIME1)

# Pinned, not a tag: a library that holds keys must not vary by the day it was fetched
SECP      := third_party/secp256k1
SECP_REV  := 46db787112beabdb5e17e0dc35680716f1057e7b
COMB      ?= -DCOMB_BLOCKS=2 -DCOMB_TEETH=5
SECP_DEFS := -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_SCHNORRSIG=1 -DECMULT_WINDOW_SIZE=2 \
             -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 $(COMB)

SIGNER_SRC := signer/wasm_main.c signer/core.c signer/address.c signer/bip32.c signer/sighash.c \
  signer/ripemd160.c signer/sha512.c signer/secp_callbacks.c signer/secp256k1_unity.c \
  parser/c/src/tx.c parser/c/src/sha256.c

all: build/parser.wasm build/signer.wasm
.PHONY: all

deps:
	mkdir -p third_party
	git clone --filter=blob:none https://github.com/bitcoin-core/secp256k1.git $(SECP)
	cd $(SECP) && git checkout --detach $(SECP_REV)
.PHONY: deps

check-deps:
	@test -d $(SECP) || { echo "run make deps first"; exit 1; }
	@cd $(SECP) && test "$$(git rev-parse HEAD)" = "$(SECP_REV)" \
	  && echo "secp256k1 at its pinned commit" || { echo "secp256k1 is NOT at $(SECP_REV)"; exit 1; }
.PHONY: check-deps

# --- which parser ---
#
# Both implementations return the same plan for every vector (parser/BENCHMARK.md has the numbers and
# why they differ). C is the default because it is what the device can afford: on WAMR's interpreter
# the Rust parse costs 3.5x the instructions, and its AOT form wants more pool than the RP2350 has.
#
#   make                      the C
#   make PARSER_IMPL=rust     the Rust
PARSER_IMPL ?= c

ifeq ($(PARSER_IMPL),rust)
build/parser.wasm: build/parser-rs.wasm
	@mkdir -p build && cp $< $@
	@shasum -a 256 $@
else
# The C keeps its own Makefile: v0.1.0 was released from it, and the build that produced those bytes
# should not become a different build by being rewritten here
build/parser.wasm: $(wildcard parser/c/src/*.c parser/c/include/*.h)
	$(MAKE) -C parser build/parser.wasm $(TOOLS)
	@mkdir -p build && cp parser/build/parser.wasm $@
	@shasum -a 256 $@
endif

# Which one the last build used, so that a stale build/parser.wasm cannot be mistaken for the other
which-parser: build/parser.wasm
	@h=$$(shasum -a 256 build/parser.wasm | cut -d' ' -f1); \
	c=$$(shasum -a 256 parser/build/parser.wasm 2>/dev/null | cut -d' ' -f1); \
	r=$$(shasum -a 256 build/parser-rs.wasm 2>/dev/null | cut -d' ' -f1); \
	if [ "$$h" = "$$c" ]; then echo "build/parser.wasm is the C ($$h)"; \
	elif [ "$$h" = "$$r" ]; then echo "build/parser.wasm is the Rust ($$h)"; \
	else echo "build/parser.wasm matches neither; rebuild it ($$h)"; exit 1; fi
.PHONY: which-parser

build/signer.wasm: $(SIGNER_SRC) signer/*.h parser/c/include/*.h | check-deps
	mkdir -p build
	$(LLVM)/clang --target=wasm32-wasip1 --sysroot=$(WASI) -nostartfiles -nodefaultlibs \
	  -Oz -Wall -Wno-unused-function -DNDEBUG $(LIME_FLAGS) -Isigner -Iparser/c/include \
	  -I$(SECP)/include -I$(SECP)/src $(SECP_DEFS) \
	  -Wl,--no-entry -Wl,--gc-sections -Wl,--strip-all -Wl,-z,stack-size=16384 \
	  -Wl,--export=__heap_base -Wl,--export=__data_end \
	  -Wl,--initial-memory=196608 -Wl,--no-growable-memory \
	  --no-wasm-opt -Wl,--keep-section=target_features \
	  -o $@ $(SIGNER_SRC) -lc $(RTLIB)/libclang_rt.builtins.a
	$(WASM_OPT) $@ -Oz -o $@
	@shasum -a 256 $@

# The structure offsets in the specs and in every host library, against what C says they are. A
# number written by hand in a document is wrong the moment a struct changes, and nothing else notices
build/layout: signer/tests/layout.c signer/core.h parser/c/include/plan.h
	@mkdir -p build
	$(CC) -Isigner -Iparser/c/include -o $@ $<

check-layout: build/layout
	python3 tools/check_layout.py $<
.PHONY: check-layout

# Vectors, fuzzing and the parser's own three host libraries
check-parser: build/parser.wasm
	$(MAKE) -C parser test $(TOOLS)
.PHONY: check-parser

check-signer-js: build/signer.wasm build/parser.wasm
	node signer/hosts/js/test.mjs
.PHONY: check-signer-js

check-signer-kotlin: build/signer.wasm build/parser.wasm
	$(MAKE) -C signer/hosts/kotlin check
.PHONY: check-signer-kotlin

check-signer-swift: build/signer.wasm build/parser.wasm
	$(MAKE) -C signer/hosts/swift check
.PHONY: check-signer-swift

# Independent hosts driving the same module have to agree byte for byte. If they do not, one of them
# is reading the layout wrong, which no single-host test would catch: a lone host's tests pass just as
# happily when the library and its expectations are wrong together.
# One shell for the whole recipe, so a guard can actually skip the rest. REQUIRE_KOTLIN=1 and
# REQUIRE_SWIFT=1 turn a missing tool into a failure; CI requires Kotlin but cannot require Swift,
# because WasmKit needs Swift 6.3 or newer and the runners do not have it
PSBT_VECTOR := parser/build/vectors/own_mixed_nwu.psbt
check-hosts-agree: build/signer.wasm build/parser.wasm
	@set -e; \
	node signer/hosts/js/dump.mjs build/signer.wasm build/parser.wasm $(PSBT_VECTOR) > build/host-js.out; \
	if command -v kotlinc >/dev/null; then \
	  $(MAKE) -s -C signer/hosts/kotlin dump.jar; \
	  $(MAKE) -s -C signer/hosts/kotlin dump PSBT=$(PWD)/$(PSBT_VECTOR) > build/host-kotlin.out; \
	  diff build/host-js.out build/host-kotlin.out && echo "JavaScript and Kotlin agree"; \
	elif [ "$(REQUIRE_KOTLIN)" = "1" ]; then echo "kotlinc not found and REQUIRE_KOTLIN=1"; exit 1; \
	else echo "kotlinc not found; skipping the Kotlin host"; fi; \
	if command -v swift >/dev/null; then \
	  $(MAKE) -s -C signer/hosts/swift dump PSBT=$(PWD)/$(PSBT_VECTOR) 2>/dev/null \
	    | grep -vE '^Building|^Build complete|^\[' > build/host-swift.out; \
	  diff build/host-js.out build/host-swift.out && echo "JavaScript and Swift agree"; \
	elif [ "$(REQUIRE_SWIFT)" = "1" ]; then echo "swift not found and REQUIRE_SWIFT=1"; exit 1; \
	else echo "swift not found; skipping the Swift host"; fi
.PHONY: check-hosts-agree

# Bitcoin Core as the oracle. Core decides what a PSBT means, so agreeing with it is worth more than
# agreeing with our own expectations. Both modules are driven from JavaScript here, so this needs
# neither a native host nor Python. Its own port, so a node already on the default one is undisturbed
BTCDIR  ?= build/btcregtest
BTCPORT ?= 18999
BTCCLI   = bitcoin-cli -datadir=$(PWD)/$(BTCDIR) -regtest -rpcport=$(BTCPORT)
check-core-diff: build/parser.wasm build/signer.wasm parser/build/vectors/own_p2wpkh_1in.psbt
	@set -e; \
	command -v bitcoind >/dev/null || { echo "bitcoind not found (brew install bitcoin)"; exit 1; }; \
	$(BTCCLI) stop >/dev/null 2>&1 || true; sleep 1; \
	rm -rf $(BTCDIR) && mkdir -p $(BTCDIR); \
	bitcoind -regtest -datadir=$(PWD)/$(BTCDIR) -rpcport=$(BTCPORT) -daemon -fallbackfee=0.0001; \
	for i in $$(seq 1 30); do $(BTCCLI) getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done; \
	$(BTCCLI) getblockchaininfo >/dev/null || { echo "the regtest node did not come up"; exit 1; }; \
	rc=0; \
	node tools/check_against_core.mjs "$(BTCCLI)" build/parser.wasm build/signer.wasm \
	  parser/build/vectors/*.psbt || rc=1; \
	$(BTCCLI) stop >/dev/null 2>&1 || true; \
	exit $$rc
.PHONY: check-core-diff

# --- the port from C to Rust, in progress ---
#
# Both are built and required to agree on every vector and on fuzzed input. The C is the reference
# until the port is complete: a port checked only against its own tests is a port whose bugs become
# its tests. See parser/rust/README.md for what has moved across so far.
RUST_TOOLCHAIN := 1.95.0
RUST_WASM := parser/rust/target/wasm32-unknown-unknown/release/jitsu_in_parser.wasm

$(RUST_WASM): $(wildcard parser/rust/src/*.rs parser/rust/src/*/*.rs) parser/rust/Cargo.toml
	cd parser/rust && rustup run $(RUST_TOOLCHAIN) cargo build --release --target wasm32-unknown-unknown



# The Rust module has to meet the same bar as the C: nothing to call, and no feature creep
# wasm-opt has to be told the features: cargo leaves no target_features section for it to read, the
# way the C build's --keep-section=target_features does
RS_FEATURES := --enable-bulk-memory-opt --enable-nontrapping-float-to-int --enable-sign-ext \
               --enable-mutable-globals --enable-multivalue --enable-extended-const
build/parser-rs.wasm: $(RUST_WASM)
	@mkdir -p build
	$(WASM_OPT) $< -Oz --strip-debug --strip-producers $(RS_FEATURES) -o $@
	@shasum -a 256 $@

# The whole 5,016-byte plan, the prevtx offsets and what finalize produces, compared against the C
# through the real ABI. Comparing the plan whole means a field this check does not know about cannot
# hide a difference
check-rust-plan: build/parser.wasm build/parser-rs.wasm parser/build/vectors/own_p2wpkh_1in.psbt
	node parser/tools/check_rust_plan.mjs build/parser.wasm build/parser-rs.wasm parser/build/vectors
.PHONY: check-rust-plan

# The suite the C is tested with, run against the Rust module. It drives the module by its exported
# names, so porting the tests was never necessary
check-rust-suite: build/parser-rs.wasm parser/build/vectors/own_p2wpkh_1in.psbt
	cd parser && node tools/run_tests.mjs ../build/parser-rs.wasm build/vectors \
	  tests/rpc_psbt.json tests/ur_vectors.json
.PHONY: check-rust-suite

check-rust-shape: build/parser-rs.wasm
	@n=$$(wasm-tools print build/parser-rs.wasm | grep -c '(import ' || true); \
	test "$$n" = "0" || { echo "the Rust module has $$n import(s)"; exit 1; }
	wasm-tools validate --features=-all,floats,saturating-float-to-int,bulk-memory-opt,-mutable-global,sign-extension \
	  build/parser-rs.wasm
	@echo "the Rust module has no imports and stays inside Lime1"
.PHONY: check-rust-shape

# The host libraries ship as plain .mjs that anyone can read and import with no build step. This
# type-checks them in place and regenerates the .d.mts beside them, failing if the committed ones are
# stale — so a TypeScript consumer gets types without this repository shipping a build artifact as
# the thing you run. TypeScript is pinned by version and by the hash of its tarball, like every
# other tool here
TS_VERSION := 5.9.3
TS_SHA     := 10e108c9cf7d5f2879053dff18515fb405abf2ccef63eaaf017d9c571687a1d3
TSC         = build/ts/package/bin/tsc

build/ts/package/bin/tsc:
	@mkdir -p build/ts
	cd build/ts && npm pack typescript@$(TS_VERSION) >/dev/null
	echo "$(TS_SHA)  build/ts/typescript-$(TS_VERSION).tgz" | (shasum -a 256 -c - || sha256sum -c -)
	cd build/ts && tar xzf typescript-$(TS_VERSION).tgz

# The figure in docs/everywhere.md
everywhere: tools/draw_everywhere.mjs
	node $< docs/everywhere.svg
.PHONY: everywhere

check-types: $(TSC)
	@set -e; \
	command -v node >/dev/null || { echo "node not found"; exit 1; }; \
	node $(TSC) -p tsconfig.json; \
	for f in parser/hosts/js/parser signer/hosts/js/signer; do \
	  diff -u $$f.d.mts build/types/$$f.d.mts \
	    || { echo "$$f.d.mts is stale: it has been regenerated, so commit the result"; exit 1; }; \
	done; \
	echo "the host libraries type-check, and the committed .d.mts files are current"
.PHONY: check-types

# What we ship has to have the right shape, checked rather than intended
check-wasm: build/parser.wasm build/signer.wasm
	python3 tools/check_wasm.py build/parser.wasm build/signer.wasm
.PHONY: check-wasm

# Builds with the pinned toolchain and requires the bytes to be the ones in checksums.txt. This is
# what ties a .wasm a host loaded back to this source; CI runs the same comparison.
check-repro: | build
	./tools/toolchain.sh >/dev/null
	@set -e; \
	for m in parser signer; do \
	  h=$$(shasum -a 256 build/$$m.wasm | cut -d' ' -f1); \
	  grep -q "$$h" checksums.txt \
	    || { echo "$$m.wasm is $$h, which is not in checksums.txt"; exit 1; }; \
	  echo "  $$m.wasm $$h"; \
	done; \
	echo "both modules match checksums.txt"
.PHONY: check-repro

test: check-types check-layout check-parser check-signer-js check-hosts-agree
	@echo
	@echo "both modules, the vectors, and the JavaScript hosts passed."
	@echo "the JVM and Swift hosts need kotlinc and Swift 6.3+: make check-signer-kotlin check-signer-swift"
.PHONY: test

clean:
	rm -rf build
	$(MAKE) -C parser clean 2>/dev/null || true
.PHONY: clean
