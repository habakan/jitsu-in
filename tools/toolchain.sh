#!/bin/sh
# Puts the toolchain for a reproducible build in build/toolchain. Pinned by version and by the hash
# of the tarball, so that someone else can produce the same bytes and therefore the same SHA-256.
set -e

WASI_SDK=34.0
BINARYEN=132
DIR=build/toolchain

case "$(uname -s)-$(uname -m)" in
Darwin-arm64) SDK_A=arm64-macos; BIN_A=arm64-macos
    SDK_SUM=9c59398106b417f8f14913380fdf0097a8cc0ff4af9eb3ce0065a859e88d49e9
    BIN_SUM=98aad827847af7ef990ed7098d885725c8e5b5aae75073403635617ae4e259aa ;;
Linux-x86_64) SDK_A=x86_64-linux; BIN_A=x86_64-linux
    SDK_SUM=b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4
    BIN_SUM=195ddc94f9bc89f45abdabb0b9eea86023d727ba90eac8b35b80f2544fc30572 ;;
*)  echo "no pinned toolchain for $(uname -s)-$(uname -m); add its hashes to use it"; exit 1 ;;
esac

sum() { shasum -a 256 "$1" 2>/dev/null || sha256sum "$1"; }

fetch() { # url, where to unpack it, the hash to expect
    [ -d "$2" ] && return 0
    mkdir -p $DIR && t=$DIR/dl.tar.gz
    curl -sL -o $t "$1"
    got=$(sum $t | cut -d' ' -f1)
    [ "$got" = "$3" ] || { echo "wrong hash for $1"; echo "  expected $3"; echo "  got      $got"; rm -f $t; exit 1; }
    tar xzf $t -C $DIR && rm $t
}

fetch "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK%%.*}/wasi-sdk-$WASI_SDK-$SDK_A.tar.gz" \
      "$DIR/wasi-sdk-$WASI_SDK-$SDK_A" "$SDK_SUM"
fetch "https://github.com/WebAssembly/binaryen/releases/download/version_$BINARYEN/binaryen-version_$BINARYEN-$BIN_A.tar.gz" \
      "$DIR/binaryen-version_$BINARYEN" "$BIN_SUM"

echo "$DIR/wasi-sdk-$WASI_SDK-$SDK_A"
