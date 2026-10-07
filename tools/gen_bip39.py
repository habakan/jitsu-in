#!/usr/bin/env python3
"""Writes signer/bip39_words.h from BIP39's english.txt, signer/tests/seedqr_vectors.h from the
published SeedQR vectors (the CompactSeedQR bytes computed here from the words), and
signer/tests/bip39_vectors.h from BIP39's reference vectors.

    curl -sSfLO https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
    curl -sSfLO https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json
    python3 tools/gen_bip39.py english.txt vectors.json
"""
import json
import hashlib
import sys

ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
VECTORS_SHA256 = "fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8"

# The SeedQR specification's vectors: the mnemonic and its Standard SeedQR digits. 7 to 9 are there
# because their CompactSeedQR bytes contain \n, \r and \r\n
VECTORS = [
    ("attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony ranch "
     "winter theme error hybrid van cereal salon goddess expire",
     "011513251154012711900771041507421289190620080870026613431420201617920614089619290300152408010643"),
    ("atom solve joy ugly ankle message setup typical bean era cactus various odor refuse element afraid "
     "meadow quick medal plate wisdom swap noble shallow",
     "011416550964188800731119157218870156061002561932122514430573003611011405110613292018175411971576"),
    ("sound federal bonus bleak light raise false engage round stock update render quote truck quality "
     "fringe palace foot recipe labor glow tortoise potato still",
     "166206750203018810361417065805941507171219081456140818651401074412730727143709940798183613501710"),
    ("forum undo fragile fade shy sign arrest garment culture tube off merit",
     "073318950739065415961602009907670428187212261116"),
    ("good battle boil exact add seed angle hurry success glad carbon whisper",
     "080301540200062600251559007008931730078802752004"),
    ("approve fruit lens brass ring actual stool coin doll boss strong rate",
     "008607501025021714880023171503630517020917211425"),
    ("dignity utility vacant shiver thought canoe feel multiply item youth actor coyote",
     "049619221923158517990268067811630950204300210397"),
    ("corn voice scrap arrow original diamond trial property benefit choose junk lock",
     "038719631547010112530489185713790169032209701051"),
    ("vocal tray giggle tool duck letter category pattern train magnet excite swamp",
     "196218530783182905421028028912901848107106301753"),
]


# Dice rolls, as the characters 1 to 6, become entropy as SHA-256 of the string, cut to 16 bytes for
# 12 words; the mnemonics are recomputed below rather than trusted
DICE = [
    ("522222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555555",
     "resource timber firm banner horror pupil frozen main pear direct pioneer broken grid core insane begin "
     "sister pony end debate task silk empty curious"),
    ("222222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555555",
     "garden uphold level clog sword globe armor issue two cute scorpion improve verb artwork blind tail raw "
     "butter combine move produce foil feature wave"),
    ("222222222222222222222222222222222222222222222555555555555555555555555555555555555555555555555555556",
     "lizard broken love tired depend eyebrow excess lonely advance father various cram ignore panic feed plunge "
     "miss regret boring unique galaxy fan detail fly"),
    ("12345612345612345612345612345612345612345612345612",
     "unveil nice picture region tragic fault cream strike tourist control recipe tourist"),
    ("11111111111111111111111111111111111111111111111111",
     "diet glad hat rural panther lawsuit act drop gallery urge where fit"),
    ("66666666666666666666666666666666666666666666666666",
     "senior morning song proud recycle toy search apple trigger lend vibrant arrest"),
]


def mnemonic_of(ent, words):
    n = len(ent) * 8 // 32
    bits = format(int.from_bytes(ent, "big"), "0%db" % (len(ent) * 8))
    bits += format(hashlib.sha256(ent).digest()[0], "08b")[:n]
    return " ".join(words[int(bits[i : i + 11], 2)] for i in range(0, len(bits), 11))


def entropy(words, index):
    n = len(words)
    bits = "".join(format(index[w], "011b") for w in words)
    ent_bits = n * 11 - n // 3
    ent = int(bits[:ent_bits], 2).to_bytes(ent_bits // 8, "big")
    want = format(hashlib.sha256(ent).digest()[0], "08b")[: n // 3]
    assert bits[ent_bits:] == want, "bad checksum: " + " ".join(words)
    return ent


def pinned(path, want):
    raw = open(path, "rb").read()
    if hashlib.sha256(raw).hexdigest() != want:
        sys.exit(path + " is not the pinned file")
    return raw


def main(path, vectors_path):
    raw = pinned(path, ENGLISH_SHA256)
    words = raw.decode().split()
    assert len(words) == 2048 and max(map(len, words)) == 8
    index = {w: i for i, w in enumerate(words)}

    with open("signer/bip39_words.h", "w") as f:
        f.write("/* Generated by tools/gen_bip39.py from BIP39's english.txt; do not edit */\n")
        f.write("#ifndef CORE_BIP39_WORDS_H\n#define CORE_BIP39_WORDS_H\n\n")
        f.write("#if defined(__has_attribute) && __has_attribute(nonstring)\n#define NONSTRING __attribute__((nonstring))\n")
        f.write("#else\n#define NONSTRING\n#endif\n")
        f.write("/* Eight bytes per word, NUL-padded: no word is longer, and it saves 2048 pointers */\n")
        f.write("static const char bip39_words[2048][8] NONSTRING = {\n")
        for i in range(0, 2048, 8):
            f.write("    " + " ".join('"%s",' % w for w in words[i : i + 8]) + "\n")
        f.write("};\n\n#endif\n")

    with open("signer/tests/seedqr_vectors.h", "w") as f:
        f.write("/* Generated by tools/gen_bip39.py from the published SeedQR vectors; do not edit */\n")
        f.write("static const struct {\n    const char *mnemonic, *digits;\n    unsigned len;\n")
        f.write("    unsigned char compact[32];\n} seedqr_vectors[] = {\n")
        for mnemonic, digits in VECTORS:
            ws = mnemonic.split()
            assert digits == "".join("%04d" % index[w] for w in ws), mnemonic
            ent = entropy(ws, index)
            f.write('    {"%s",\n     "%s",\n     %d,\n     {%s}},\n'
                    % (mnemonic, digits, len(ent), ", ".join("0x%02x" % b for b in ent)))
        f.write("};\n")

    # each is [entropy, mnemonic, seed with the passphrase "TREZOR", xprv]
    english = json.loads(pinned(vectors_path, VECTORS_SHA256))["english"]
    with open("signer/tests/bip39_vectors.h", "w") as f:
        f.write("/* Generated by tools/gen_bip39.py from BIP39's reference vectors; do not edit */\n")
        f.write("static const struct {\n    const char *mnemonic, *seed, *entropy;\n} bip39_vectors[] = {\n")
        for ent, mnemonic, seed, _ in english:
            assert mnemonic_of(bytes.fromhex(ent), words) == mnemonic
            f.write('    {"%s",\n     "%s",\n     "%s"},\n' % (mnemonic, seed, ent))
        f.write("};\n\n")
        f.write("static const struct {\n    const char *rolls, *mnemonic;\n} dice_vectors[] = {\n")
        for rolls, mnemonic in DICE:
            n = 16 if len(mnemonic.split()) == 12 else 32
            assert mnemonic_of(hashlib.sha256(rolls.encode()).digest()[:n], words) == mnemonic, rolls
            f.write('    {"%s",\n     "%s"},\n' % (rolls, mnemonic))
        f.write("};\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
