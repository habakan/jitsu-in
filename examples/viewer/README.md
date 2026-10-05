# Browser viewer

This example reads a PSBT or animated QR (UR), displays the transaction plan, and holds no keys. It
builds a single HTML file that works offline, including from `file://` on desktop browsers.

```sh
git submodule update --init examples/viewer/vendor/quirc
make deps
make viewer
```

The page embeds the parser module built by this repository, a small address encoder, and quirc for QR
decoding. It displays the SHA-256 of each embedded module. Safari uses the bundled jsQR decoder when
the browser does not provide `BarcodeDetector`.

The viewer is for inspecting a transaction. It does not sign, and its display is not a trusted signing
device.
