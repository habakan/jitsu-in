# /// script
# dependencies = []
# ///
"""Bundle the browser viewer and its WebAssembly modules into one offline HTML file."""
import base64
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VIEWER = Path(__file__).resolve().parent
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build/viewer.html"
parser = (ROOT / "build/parser.wasm").read_bytes()
address = (VIEWER / "build/address.wasm").read_bytes()
qr = (VIEWER / "build/qr.wasm").read_bytes()
jsqr = (VIEWER / "vendor/jsQR.min.js").read_text()  # Safari has no built-in QR decoder
# A file:// page cannot load an ES module, so embed the host library as a plain script.
host = re.sub(r"^export ", "", (ROOT / "parser/hosts/js/parser.mjs").read_text(), flags=re.M)
page = (VIEWER / "viewer.html").read_text()

html = (page.replace("__PARSER_WASM__", base64.b64encode(parser).decode())
            .replace("__ADDRESS_WASM__", base64.b64encode(address).decode())
            .replace("__PARSER_SHA256__", hashlib.sha256(parser).hexdigest())
            .replace("__QR_WASM__", base64.b64encode(qr).decode())
            .replace("__ADDRESS_SHA256__", hashlib.sha256(address).hexdigest())
            .replace("__QR_SHA256__", hashlib.sha256(qr).hexdigest())
            .replace("__JSQR_JS__", jsqr)
            .replace("__PARSER_HOST_JS__", host))
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(html)
print(f"{OUT}: {len(html) / 1024:.0f}KB "
      f"(parser.wasm {len(parser)}B, address.wasm {len(address)}B, qr.wasm {len(qr)}B)")
print(f"parser.wasm sha256 {hashlib.sha256(parser).hexdigest()}")
