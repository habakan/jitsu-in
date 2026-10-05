ROOT   := ../../../..
SIGNER ?= $(ROOT)/build/signer.wasm
PARSER ?= $(ROOT)/build/parser.wasm
PSBT   ?= $(ROOT)/build/psbt/own_mixed_nwu.psbt
SIGNED ?= $(ROOT)/build/psbt/own_mixed_nwu.signed

check:
	swift run SignerCheck $(SIGNER) $(PARSER) $(PSBT) $(SIGNED)

# Prints what the module reported, so this host's output can be diffed against the other two
dump:
	@swift run SignerCheck --dump $(SIGNER) $(PARSER) $(PSBT)

clean:
	rm -rf .build
.PHONY: check dump clean
