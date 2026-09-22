# Needs clang with the wasm32 target and a wasi-libc sysroot. With Homebrew: llvm / lld / wasi-libc / wasi-runtimes
LLVM    ?= /opt/homebrew/opt/llvm/bin
WASI    ?= /opt/homebrew/opt/wasi-libc/share/wasi-sysroot
RTLIB   ?= /opt/homebrew/opt/wasi-runtimes/share/wasi-runtimes/lib/wasm32-unknown-wasip1
SRC     := src/psbt.c src/tx.c src/sha256.c

# The input and output buffers (just over 32 KB each) need two pages of linear memory. With no memory.grow,
# WAMR's shrunk-memory option trims it down to __heap_base
build/parser.wasm: $(SRC) include/*.h
	mkdir -p build
	$(LLVM)/clang --target=wasm32-wasip1 --sysroot=$(WASI) -nostartfiles -nodefaultlibs -Oz -Wall -Wextra \
	  -Iinclude -Wl,--no-entry -Wl,--gc-sections -Wl,--strip-all -Wl,-z,stack-size=16384 \
	  -Wl,--export=__heap_base -Wl,--export=__data_end -Wl,--initial-memory=131072 -Wl,--max-memory=131072 \
	  -o $@ $(SRC) -lc $(RTLIB)/libclang_rt.builtins.a
	shasum -a 256 $@

build/vectors/own_p2wpkh_1in.psbt: tools/gen_vectors.py tests/rpc_psbt.json
	rm -rf build/vectors && uv run -q $< tests/rpc_psbt.json build/vectors

test: build/parser.wasm build/vectors/own_p2wpkh_1in.psbt
	uv run -q tools/run_tests.py build/parser.wasm build/vectors tests/rpc_psbt.json

clean:
	rm -rf build
.PHONY: test clean
