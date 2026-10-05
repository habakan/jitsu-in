# Chicory comes from Maven Central and its hash is checked. No Gradle on purpose: that would mean
# committing gradle-wrapper.jar, and a binary blob is not something this repository should ask you to trust
CHICORY := 1.4.0
RUNTIME_SHA := 81245b1f832afcf52169e655d2db6a07009864dba352b174b90a444bf096bf6e
WASM_SHA    := a850df5e77f60411648fd970144f825517a2c076dbb807ff6de95c6cfa439968
BASE := https://repo1.maven.org/maven2/com/dylibso/chicory
CP := lib/runtime-$(CHICORY).jar:lib/wasm-$(CHICORY).jar
# kotlinc brings its own JVM to compile with, but running needs a java that works. macOS ships a
# /usr/bin/java stub that is on PATH and fails with "Unable to locate a Java Runtime", so a real one
# is looked for first; Homebrew's openjdk is keg-only and therefore never on PATH
JAVA ?= $(firstword $(wildcard /opt/homebrew/opt/openjdk/bin/java) \
                    $(shell command -v java 2>/dev/null))
WASM ?= ../../build/parser.wasm
PSBT ?= ../../build/vectors/own_p2wpkh_1in.psbt
FP   ?= 73c5da0a

check: test.jar
	$(JAVA) -cp "test.jar:$(CP)" TestKt $(WASM) $(dir $(PSBT))

test.jar: Parser.kt Test.kt $(subst :, ,$(CP))
	kotlinc Parser.kt Test.kt -cp "$(CP)" -include-runtime -d $@

run: plandump.jar
	$(JAVA) -cp "plandump.jar:$(CP)" PlanDumpKt $(WASM) $(PSBT) $(FP)

plandump.jar: Parser.kt PlanDump.kt $(subst :, ,$(CP))
	kotlinc Parser.kt PlanDump.kt -cp "$(CP)" -include-runtime -d $@

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
	rm -rf lib plandump.jar test.jar
.PHONY: run check clean
