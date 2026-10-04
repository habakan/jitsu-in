# Chicory comes from Maven Central and its hash is checked. No Gradle on purpose: that would mean
# committing gradle-wrapper.jar, and a binary blob is not something this repository should ask you to trust
CHICORY := 1.4.0
RUNTIME_SHA := 81245b1f832afcf52169e655d2db6a07009864dba352b174b90a444bf096bf6e
WASM_SHA    := a850df5e77f60411648fd970144f825517a2c076dbb807ff6de95c6cfa439968
BASE := https://repo1.maven.org/maven2/com/dylibso/chicory
CP := lib/runtime-$(CHICORY).jar:lib/wasm-$(CHICORY).jar
ROOT   := ../../../..
SIGNER ?= $(ROOT)/build/signer.wasm
PARSER ?= $(ROOT)/build/parser.wasm
PSBT   ?= $(ROOT)/build/psbt/own_mixed_nwu.psbt
SIGNED ?= $(ROOT)/build/psbt/own_mixed_nwu.signed

dump: dump.jar
	@java -cp "dump.jar:$(CP)" DumpKt $(SIGNER) $(PARSER) $(PSBT)

dump.jar: Signer.kt Dump.kt $(subst :, ,$(CP))
	kotlinc Signer.kt Dump.kt -cp "$(CP)" -include-runtime -d $@

check: test.jar
	java -cp "test.jar:$(CP)" TestKt $(SIGNER) $(PARSER) $(PSBT) $(SIGNED)

test.jar: Signer.kt Test.kt $(subst :, ,$(CP))
	kotlinc Signer.kt Test.kt -cp "$(CP)" -include-runtime -d $@

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
	rm -rf lib test.jar dump.jar
.PHONY: check dump clean
