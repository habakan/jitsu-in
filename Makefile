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
  parser/src/tx.c parser/src/sha256.c

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

# The parser keeps its own Makefile: it was released from it, and the build that produced v0.1.0
# should not become a different build by being rewritten here
build/parser.wasm: $(wildcard parser/src/*.c parser/include/*.h)
	$(MAKE) -C parser build/parser.wasm $(TOOLS)
	@mkdir -p build && cp parser/build/parser.wasm $@

build/signer.wasm: $(SIGNER_SRC) signer/*.h parser/include/*.h | check-deps
	mkdir -p build
	$(LLVM)/clang --target=wasm32-wasip1 --sysroot=$(WASI) -nostartfiles -nodefaultlibs \
	  -Oz -Wall -Wno-unused-function -DNDEBUG $(LIME_FLAGS) -Isigner -Iparser/include \
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
build/layout: signer/tests/layout.c signer/core.h parser/include/plan.h
	@mkdir -p build
	$(CC) -Isigner -Iparser/include -o $@ $<

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

# What we ship has to have the right shape, checked rather than intended
check-wasm: build/parser.wasm build/signer.wasm
	python3 tools/check_wasm.py build/parser.wasm build/signer.wasm
.PHONY: check-wasm

check-repro:
	./tools/toolchain.sh >/dev/null
	@echo "see the signer repository for the five-module reproducible build"
.PHONY: check-repro

test: check-layout check-parser check-signer-js check-hosts-agree
	@echo
	@echo "both modules, the vectors, and the JavaScript hosts passed."
	@echo "the JVM and Swift hosts need kotlinc and Swift 6.3+: make check-signer-kotlin check-signer-swift"
.PHONY: test

clean:
	rm -rf build
	$(MAKE) -C parser clean 2>/dev/null || true
.PHONY: clean
