WASM ?= ../../build/parser.wasm
PSBT ?= ../../build/vectors/own_p2wpkh_1in.psbt
FP   ?= 73c5da0a

run:
	swift run PlanDump $(WASM) $(PSBT) $(FP)

check:
	swift run ParserCheck $(WASM) $(dir $(PSBT))

clean:
	rm -rf .build
.PHONY: run check clean
