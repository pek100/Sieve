/**
 * Generated app icons for the mock source (`?icons=1`), so the browser and
 * e2e can exercise the real-icon path without Windows. Each is a PNG made
 * here (a filled disc with a transparent background, in one of a few hues
 * picked by the exe path), at 32 and 64 px like the Rust command's answer.
 * Deterministic: same path, same bytes.
 */
import type { AppIcon } from "./protocol";

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function adler32(bytes: Uint8Array): number {
  let a = 1;
  let b = 0;
  for (const x of bytes) {
    a = (a + x) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

const u32 = (n: number) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];

function chunk(type: string, data: Uint8Array): number[] {
  const body = new Uint8Array([...type].map((c) => c.charCodeAt(0)).concat([...data]));
  return [...u32(data.length), ...body, ...u32(crc32(body))];
}

/** zlib stream of stored (uncompressed) deflate blocks: valid PNG data with no compressor. */
function zlibStored(raw: Uint8Array): Uint8Array {
  const out: number[] = [0x78, 0x01];
  for (let i = 0; i < raw.length || i === 0; i += 65535) {
    const block = raw.subarray(i, i + 65535);
    const last = i + 65535 >= raw.length ? 1 : 0;
    out.push(last, block.length & 0xff, block.length >>> 8, ~block.length & 0xff, (~block.length >>> 8) & 0xff, ...block);
  }
  out.push(...u32(adler32(raw)));
  return new Uint8Array(out);
}

/** An RGBA image as PNG bytes. */
export function encodePng(size: number, rgba: Uint8Array): Uint8Array {
  const raw = new Uint8Array(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) raw.set(rgba.subarray(y * size * 4, (y + 1) * size * 4), y * (size * 4 + 1) + 1);
  const ihdr = new Uint8Array([...u32(size), ...u32(size), 8, 6, 0, 0, 0]);
  return new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, ...chunk("IHDR", ihdr), ...chunk("IDAT", zlibStored(raw)), ...chunk("IEND", new Uint8Array())]);
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
export function base64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    for (let k = 0; k < 4; k++) s += k <= bytes.length - i ? B64[(n >>> (18 - 6 * k)) & 63] : "=";
  }
  return s;
}

/** A few hues as RGB components (a stand-in for real icons' colours; not UI colours). */
const HUES: readonly (readonly [number, number, number])[] = [
  [66, 133, 244],
  [234, 67, 53],
  [251, 188, 5],
  [52, 168, 83],
  [155, 89, 182],
];

function disc(size: number, [r, g, b]: readonly [number, number, number]): Uint8Array {
  const px = new Uint8Array(size * size * 4);
  const c = (size - 1) / 2;
  const radius = size * 0.44;
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++) {
      // Anti-aliased edge: alpha falls off over one pixel.
      const d = Math.hypot(x - c, y - c);
      const a = Math.max(0, Math.min(1, radius - d + 0.5));
      px.set([r, g, b, Math.round(a * 255)], (y * size + x) * 4);
    }
  return px;
}

/** The generated icon for an exe path. */
export function mockIcon(exe: string): AppIcon {
  let h = 0;
  for (let i = 0; i < exe.length; i++) h = (h * 31 + exe.charCodeAt(i)) >>> 0;
  const hue = HUES[h % HUES.length];
  return { x1: base64(encodePng(32, disc(32, hue))), x2: base64(encodePng(64, disc(64, hue))) };
}
