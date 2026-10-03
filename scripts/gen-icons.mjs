#!/usr/bin/env node
/**
 * Generates the extension's PNG icons from code, so the pixels that ship are reviewable as source rather
 * than taken on trust. Draws a magnifying lens scanning a fish on an indigo tile: the lens is what the
 * extension does, the fish is what it is looking for, and the two waves off the lens are it speaking up.
 * Waves rather than an exclamation mark or a speech bubble with one in it, which would read as a warning
 * on a message nobody has scored.
 *
 * Indigo rather than green, amber or red because those three are the risk bands; a brand colour that
 * resembled one would make the toolbar icon read as a verdict before any message was scored.
 *
 * Every build reruns this into assets/icons/. The PNGs there are also committed, because the README shows
 * icon128.png and GitHub can only render a file that is in the repository. The output is deterministic, so
 * a build leaves them byte-identical; a diff in assets/icons/ after building means this file changed and
 * the regenerated icons belong in the same commit.
 *
 * docs/assets/hero.svg draws the same icon as vectors from the constants below, in the same -1..1 space,
 * because GitHub shows the banner at sizes no PNG here would be sharp at. Change a shape or colour here
 * and change it there.
 */
import { deflateSync } from 'node:zlib';
import { writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outdir = path.join(root, 'assets/icons');

const BG_LIGHT = [99, 102, 241];
const BG_DARK = [59, 31, 140];
const GLASS_CENTRE = [55, 48, 163];
const GLASS_EDGE = [30, 27, 75];
const RIM_LIGHT = [255, 255, 255];
const RIM_SHADE = [199, 210, 254];
const FISH_LIGHT = [253, 164, 175];
const FISH_DARK = [225, 29, 72];
const INK = [30, 27, 75];
const WHITE = [255, 255, 255];

function crc32(buf) {
  let c = ~0;
  for (const byte of buf) {
    c ^= byte;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function encodePng(size, pixels) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // truecolour + alpha
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    const rowStart = y * (size * 4 + 1);
    raw[rowStart] = 0; // no filter
    pixels.copy(raw, rowStart + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** Signed distance to a rounded rectangle centred at (0,0) with half-extents (hx,hy). */
function sdRoundRect(x, y, hx, hy, r) {
  const dx = Math.abs(x) - (hx - r);
  const dy = Math.abs(y) - (hy - r);
  const ox = Math.max(dx, 0);
  const oy = Math.max(dy, 0);
  return Math.hypot(ox, oy) + Math.min(Math.max(dx, dy), 0) - r;
}

/** Distance to the segment (ax,ay)-(bx,by), and how far along it (0..1) the nearest point lies. */
function segment(x, y, ax, ay, bx, by) {
  const vx = bx - ax;
  const vy = by - ay;
  const t = Math.min(Math.max(((x - ax) * vx + (y - ay) * vy) / (vx * vx + vy * vy), 0), 1);
  return { d: Math.hypot(x - ax - vx * t, y - ay - vy * t), t };
}

function inTriangle(x, y, [ax, ay], [bx, by], [cx, cy]) {
  const d1 = (x - bx) * (ay - by) - (ax - bx) * (y - by);
  const d2 = (x - cx) * (by - cy) - (bx - cx) * (y - cy);
  const d3 = (x - ax) * (cy - ay) - (cx - ax) * (y - ay);
  return !((d1 < 0 || d2 < 0 || d3 < 0) && (d1 > 0 || d2 > 0 || d3 > 0));
}

const clamp01 = (v) => Math.min(Math.max(v, 0), 1);

function mix(a, b, t) {
  return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
}

// Geometry, in a space where the tile spans -1..1 and y points down.
const LENS = { x: -0.14, y: -0.14, outer: 0.56, inner: 0.43 };
const HANDLE = { ax: 0.29, ay: 0.29, bx: 0.62, by: 0.62, r: 0.12 };
// The fish body is a vesica, the overlap of two circles, which gives the pointed nose and tail root.
const FISH = { x: -0.22, y: -0.11, r: 0.27, d: 0.15, scale: 1.25 };
const SCAN_Y = -0.08;
// Two arcs about the lens centre, opening up and right into the tile's one empty corner. Angles are in
// radians with y down, so negative is above the lens.
const WAVES = { a0: -1.13, a1: -0.44, w: 0.075, radii: [0.66, 0.8] };

/** Distance to an arc of radius r about the lens centre between angles a0 and a1, with round ends. */
function arc(x, y, r, a0, a1) {
  const dx = x - LENS.x;
  const dy = y - LENS.y;
  const a = Math.atan2(dy, dx);
  if (a >= a0 && a <= a1) return Math.abs(Math.hypot(dx, dy) - r);
  const end = (t) => Math.hypot(dx - r * Math.cos(t), dy - r * Math.sin(t));
  return Math.min(end(a0), end(a1));
}

/**
 * The colour at one point of the icon, or null outside the tile. `detail` drops features that would
 * smear into noise at small sizes: 0 is the lens, shadow and fish (16px), 1 adds the waves (32px), 2
 * adds the eye, gill, scan line and glint.
 */
function shade(x, y, detail) {
  if (sdRoundRect(x, y, 0.96, 0.96, 0.4) > 0) return null;
  let c = mix(BG_LIGHT, BG_DARK, clamp01((x + y + 2) / 4));
  c = mix(c, WHITE, 0.12 * clamp01(-y - 0.2));

  const dl = Math.hypot(x - LENS.x, y - LENS.y);
  const grip = segment(x, y, HANDLE.ax, HANDLE.ay, HANDLE.bx, HANDLE.by);

  // A soft shadow below and right of the lens lifts it off the tile.
  const sl = Math.hypot(x - LENS.x - 0.05, y - LENS.y - 0.07) - LENS.outer;
  const sh = segment(x - 0.05, y - 0.07, HANDLE.ax, HANDLE.ay, HANDLE.bx, HANDLE.by).d - HANDLE.r;
  c = mix(c, INK, 0.45 * (1 - clamp01(Math.min(sl, sh) / 0.09 + 0.5)));

  // The outer wave is fainter, so the pair reads as a signal fading with distance rather than two rings.
  for (const [i, r] of WAVES.radii.entries()) {
    if (detail >= 1 && arc(x, y, r, WAVES.a0, WAVES.a1) <= WAVES.w / 2) return mix(RIM_LIGHT, c, i * 0.35);
  }

  if (grip.d <= HANDLE.r && dl > LENS.inner) {
    // The collar nearest the lens stays light; the grip beyond it is a darker band.
    const base = grip.t < 0.22 ? RIM_SHADE : mix(RIM_SHADE, BG_DARK, 0.6);
    return mix(base, WHITE, 0.6 * clamp01(1 - grip.d / HANDLE.r - 0.3));
  }

  if (dl > LENS.outer) return c;
  if (dl > LENS.inner) {
    return mix(RIM_LIGHT, RIM_SHADE, clamp01((x - LENS.x + y - LENS.y) / (2 * LENS.outer) + 0.5));
  }

  c = mix(GLASS_CENTRE, GLASS_EDGE, clamp01(dl / LENS.inner) ** 1.5);

  const fx = (x - FISH.x) / FISH.scale;
  const fy = (y - FISH.y) / FISH.scale;
  const halfH = FISH.r - FISH.d;
  const body = Math.hypot(fx, fy - FISH.d) <= FISH.r && Math.hypot(fx, fy + FISH.d) <= FISH.r;
  const tail = inTriangle(fx, fy, [0.15, 0], [0.31, -0.13], [0.31, 0.13]);
  const fin = inTriangle(fx, fy, [-0.06, -halfH + 0.02], [0.06, -halfH - 0.09], [0.1, -halfH + 0.04]);
  if (body || tail || fin) {
    const depth = clamp01((fy + halfH) / (2 * halfH)) * 0.85 + (tail || fin ? 0.15 : 0);
    c = mix(FISH_LIGHT, FISH_DARK, depth);
    if (detail >= 2) {
      const gill = Math.hypot(fx + 0.02, fy) - 0.1;
      if (Math.abs(gill) < 0.012 && fx < -0.06) c = mix(c, FISH_DARK, 0.7);
      const eye = Math.hypot(fx + 0.15, fy + 0.025);
      if (eye < 0.045) c = eye < 0.024 ? INK : WHITE;
    }
  }

  if (detail >= 2) {
    // The scan line, with a glow that fades out above and below it.
    const band = Math.abs(y - SCAN_Y);
    c = mix(c, RIM_SHADE, 0.85 * Math.exp(-((band / 0.012) ** 2)) + 0.18 * Math.exp(-((band / 0.07) ** 2)));
    // Glint: a short arc of reflected light at the upper left of the glass.
    const a = Math.atan2(y - LENS.y, x - LENS.x);
    if (Math.abs(dl - LENS.inner + 0.07) < 0.025 && a > -2.7 && a < -1.9) c = mix(c, WHITE, 0.7);
  }
  return c;
}

function render(size) {
  const pixels = Buffer.alloc(size * size * 4);
  const detail = size <= 16 ? 0 : size <= 32 ? 1 : 2;
  // The Web Store asks for 96px of artwork inside a 128px icon; the toolbar sizes fill their square.
  const extent = size === 128 ? 0.75 : 1;
  const n = 4;

  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0;
      let g = 0;
      let b = 0;
      let hits = 0;
      for (let sy = 0; sy < n; sy++) {
        for (let sx = 0; sx < n; sx++) {
          const x = (((px + (sx + 0.5) / n) / size) * 2 - 1) / extent;
          const y = (((py + (sy + 0.5) / n) / size) * 2 - 1) / extent;
          const c = shade(x, y, detail);
          if (!c) continue;
          r += c[0];
          g += c[1];
          b += c[2];
          hits++;
        }
      }
      if (hits === 0) continue;
      const i = (py * size + px) * 4;
      // Averaged over covered samples only, so the tile's edge fades in alpha rather than towards black.
      pixels[i] = Math.round(r / hits);
      pixels[i + 1] = Math.round(g / hits);
      pixels[i + 2] = Math.round(b / hits);
      pixels[i + 3] = Math.round((255 * hits) / (n * n));
    }
  }
  return encodePng(size, pixels);
}

await mkdir(outdir, { recursive: true });
for (const size of [16, 32, 48, 128]) {
  await writeFile(path.join(outdir, `icon${size}.png`), render(size));
}
