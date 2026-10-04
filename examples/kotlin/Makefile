# Chicory は Maven Central から取り、ハッシュを検証する。Gradle を使わないのは、
# wrapper の jar（バイナリ）を鍵を扱うリポジトリに置きたくないため
CHICORY := 1.4.0
RUNTIME_SHA := 81245b1f832afcf52169e655d2db6a07009864dba352b174b90a444bf096bf6e
WASM_SHA    := a850df5e77f60411648fd970144f825517a2c076dbb807ff6de95c6cfa439968
BASE := https://repo1.maven.org/maven2/com/dylibso/chicory
CP := lib/runtime-$(CHICORY).jar:lib/wasm-$(CHICORY).jar
WASM ?= ../../build/parser.wasm
PSBT ?= ../../build/vectors/own_p2wpkh_1in.psbt
FP   ?= 73c5da0a

run: plandump.jar
	java -cp "plandump.jar:$(CP)" PlanDumpKt $(WASM) $(PSBT) $(FP)

plandump.jar: PlanDump.kt $(subst :, ,$(CP))
	kotlinc $< -cp "$(CP)" -include-runtime -d $@

define fetch
	mkdir -p lib
	curl -sL -o $@ $(BASE)/$(1)/$(CHICORY)/$(1)-$(CHICORY).jar
	echo "$(2)  $@" | (shasum -a 256 -c - || sha256sum -c -)
endef

lib/runtime-$(CHICORY).jar:
	$(call fetch,runtime,$(RUNTIME_SHA))

lib/wasm-$(CHICORY).jar:
	$(call fetch,wasm,$(WASM_SHA))

clean:
	rm -rf lib plandump.jar
.PHONY: run clean
