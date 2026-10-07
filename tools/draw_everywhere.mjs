// Draws the "same bytes, everywhere" figure. Mermaid grows downwards and loses the centre, so the
// radial layout is assembled by hand.
// Usage: node tools/draw_everywhere.mjs docs/everywhere.svg
import { readFileSync, writeFileSync } from "node:fs";

const W = 940, H = 640;
const CX = W / 2, CY = H / 2 + 14;
const RX = 322, RY = 212;              // the ellipse the platforms sit on
const CARD_W = 246, CARD_H = 80;

// name, runtime, what actually runs as wasm there, verified, angle (degrees, 0 is right), icon.
// The third line is not decoration: the device runs the signer as native C, and the browser viewer
// holds no keys, so claiming both modules everywhere would be false.
const PLATFORMS = [
  ["Bare metal MCU", "WAMR · RP2350 · no OS", "parser.wasm · signer native", true, -90, "chip"],
  ["Android", "Chicory · a plain JAR, no NDK", "parser.wasm · signer.wasm", true, -30, "phone"],
  ["iOS", "WasmKit · pure Swift", "parser.wasm · signer.wasm", true, 30, "phone"],
  ["Node / CI", "V8 + WAMR · parser vectors", "both (V8) · parser (WAMR)", true, 90, "terminal"],
  ["Linux / macOS", "WAMR · the same interpreter", "parser.wasm · signer.wasm", true, 150, "laptop"],
  ["Web viewer", "the browser's own engine", "parser.wasm · read-only", false, 210, "globe"],
];

const MODULES = [["parser.wasm", "15,579 B"], ["signer.wasm", "74,416 B"]];
const NAME = "jitsu-in";

// Brand logos are trademarked, so each platform gets a shape that says what kind it is
function icon(kind, x, y, size, color) {
  const k = size / 24;
  const pins = [[10,7,10,4],[14,7,14,4],[10,17,10,20],[14,17,14,20],
                [7,10,4,10],[7,14,4,14],[17,10,20,10],[17,14,20,14]];
  const d = {
    chip: ['<rect x="7" y="7" width="10" height="10" rx="1.5"/>',
           ...pins.map(([a,b,c,e]) => `<line x1="${a}" y1="${b}" x2="${c}" y2="${e}"/>`)],
    phone: ['<rect x="7" y="3" width="10" height="18" rx="2"/>',
            '<line x1="10.5" y1="5.5" x2="13.5" y2="5.5"/>', '<circle cx="12" cy="18" r="0.9"/>'],
    globe: ['<circle cx="12" cy="12" r="8.5"/>', '<ellipse cx="12" cy="12" rx="4" ry="8.5"/>',
            '<line x1="3.5" y1="12" x2="20.5" y2="12"/>',
            '<path d="M5.5 7 Q12 10 18.5 7"/>', '<path d="M5.5 17 Q12 14 18.5 17"/>'],
    laptop: ['<rect x="4" y="5" width="16" height="10" rx="1.5"/>', '<path d="M2 18.5 h20"/>',
             '<path d="M9.5 15.5 h5"/>'],
    terminal: ['<rect x="3" y="4.5" width="18" height="15" rx="2"/>',
               '<path d="M7 9.5 l3 2.5 l-3 2.5"/>', '<line x1="12.5" y1="15" x2="17" y2="15"/>'],
  }[kind];
  return `<g transform="translate(${x},${y}) scale(${k})" fill="none" stroke="${color}" ` +
         `stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${d.join("")}</g>`;
}

const WASM_PATH = "M66.12,0c0,.19,0,.38,0,.58a12.34,12.34,0,1,1-24.68,0c0-.2,0-.39,0-.58H0V107.62H10" +
  "7.62V0ZM51.38,96.1,46.14,70.17H46L40.39,96.1H33.18L25,58h7.13L37,83.93h.09L42.94,58h6.67L54.9,8" +
  "4.25H55L60.55,58h7L58.46,96.1Zm39.26,0-2.43-8.48H75.4L73.53,96.1H66.36L75.59,58H86.83L98,96.1Z";
const WASM_NOTCH = "79.87 67.39 76.76 81.37 86.44 81.37 82.87 67.39 79.87 67.39";
const BITCOIN_MARK = readFileSync(new URL("../docs/bitcoin.svg", import.meta.url), "utf8")
  .match(/<g[^>]*>([\s\S]*?)<\/g>/)[1];

function wasmLogo(cx, cy, size) {
  const k = size / 107.62;
  return `<g transform="translate(${cx - size / 2},${cy - size / 2}) scale(${k})" fill="#654FF0">` +
    `<path d="${WASM_PATH}"/><polygon points="${WASM_NOTCH}"/></g>`;
}

function bitcoinLogo(cx, cy, size) {
  const k = size / 64;
  return `<g transform="translate(${cx - size / 2},${cy - size / 2}) scale(${k})">${BITCOIN_MARK}</g>`;
}

const FONT = "Hiragino Sans, Noto Sans JP, sans-serif";
const BG = "#ffffff", FG = "#1a1d24", DIM = "#6b7280", LINE = "#d4d8e0";
const OK_FILL = "#f2fbf5", OK_LINE = "#2f9e5e", OK_FG = "#166534";
const TODO_FILL = "#fafafa", TODO_LINE = "#cbd2dc";
const HUB_FILL = "#faf8ff", HUB_LINE = "#654FF0";

const s = [`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" ` +
           `viewBox="0 0 ${W} ${H}" font-family="${FONT}"><rect width="${W}" height="${H}" fill="${BG}"/>`];

s.push(`<text x="${W / 2}" y="40" fill="${FG}" font-size="21" text-anchor="middle">` +
       `The same bytes run everywhere</text>`);
s.push(`<text x="${W / 2}" y="63" fill="${DIM}" font-size="13" text-anchor="middle">` +
       `Zero imports. No WASI, no JS polyfill, nothing to call.</text>`);

// Spokes first, so the cards sit on top of them
const pos = PLATFORMS.map(([, , , done, deg]) => {
  const r = (deg * Math.PI) / 180;
  const x = CX + RX * Math.cos(r), y = CY + RY * Math.sin(r);
  s.push(`<line x1="${CX}" y1="${CY}" x2="${x}" y2="${y}" stroke="${done ? OK_LINE : LINE}" ` +
         `stroke-width="${done ? 2.2 : 1.6}" opacity="${done ? 0.5 : 0.35}"/>`);
  return [x, y];
});

// The hub: the logo, the name, and the two files it stands for
const hw = 258, hh = 196;
const top = CY - hh / 2;
s.push(`<rect x="${CX - hw / 2}" y="${top}" width="${hw}" height="${hh}" rx="12" ` +
       `fill="${HUB_FILL}" stroke="${HUB_LINE}" stroke-width="1.8"/>`);
s.push(wasmLogo(CX - 23, top + 44, 36));
s.push(bitcoinLogo(CX + 23, top + 44, 36));
s.push(`<text x="${CX}" y="${top + 94}" fill="${HUB_LINE}" font-size="20" text-anchor="middle" ` +
       `letter-spacing="0.5">${NAME}</text>`);
s.push(`<line x1="${CX - hw / 2 + 22}" y1="${top + 108}" x2="${CX + hw / 2 - 22}" y2="${top + 108}" ` +
       `stroke="${HUB_LINE}" stroke-width="1" opacity="0.3"/>`);
MODULES.forEach(([n, sz], i) => {
  const y = top + 132 + i * 24;
  s.push(`<text x="${CX - hw / 2 + 22}" y="${y}" fill="${FG}" font-size="13.5">${n}</text>`);
  s.push(`<text x="${CX + hw / 2 - 22}" y="${y}" fill="${DIM}" font-size="12.5" text-anchor="end">${sz}</text>`);
});
s.push(`<text x="${CX}" y="${CY + hh / 2 - 16}" fill="${DIM}" font-size="11.5" text-anchor="middle">` +
       `the same file, wherever it runs</text>`);

// The platforms
PLATFORMS.forEach(([name, rt, runs, done, , kind], i) => {
  const [x, y] = pos[i];
  const [fill, stroke] = done ? [OK_FILL, OK_LINE] : [TODO_FILL, TODO_LINE];
  const left = x - CARD_W / 2;
  s.push(`<rect x="${left}" y="${y - CARD_H / 2}" width="${CARD_W}" height="${CARD_H}" rx="9" ` +
         `fill="${fill}" stroke="${stroke}" stroke-width="1.6"/>`);
  s.push(icon(kind, left + 15, y - 17, 34, done ? OK_LINE : DIM));
  const tx = left + 62;
  s.push(`<text x="${tx}" y="${y - 12}" fill="${done ? OK_FG : FG}" font-size="15">${name}</text>`);
  s.push(`<text x="${tx}" y="${y + 7}" fill="${DIM}" font-size="11.5">${rt}</text>`);
  s.push(`<text x="${tx}" y="${y + 25}" fill="${done ? HUB_LINE : DIM}" font-size="10.5">${runs}</text>`);
});

s.push(`<text x="26" y="${H - 22}" fill="${DIM}" font-size="11.5">` +
       `green = run, and the output checked against the others &#183; grey = works, but not a recommended place for it</text>`);
s.push("</svg>");

const out = process.argv[2] ?? "docs/everywhere.svg";
writeFileSync(out, s.join("\n"));
console.log(`${out}: ${PLATFORMS.length} platforms, ${W}x${H}`);
