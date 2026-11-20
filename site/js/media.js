/** Small carrier files drawn in JavaScript: pictures and sound with real texture. */

/** A seeded xorshift32 generator returning floats in [0, 1). */
function noise(seed) {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 4294967296;
  };
}

const clamp = (v) => (v < 0 ? 0 : v > 255 ? 255 : Math.round(v));

/** RGB pixels (row-major, top row first) of a gradient with noise, a sun and stripes. */
export function drawPicture(width, height, seed = 7) {
  const rnd = noise(seed);
  const rgb = new Uint8Array(width * height * 3);
  const cx = width * 0.7;
  const cy = height * 0.35;
  const r = Math.min(width, height) * 0.18;
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const t = y / height;
      let red = 40 + 150 * t + 30 * Math.sin(x / 9);
      let green = 90 + 80 * (x / width) + 20 * Math.cos(y / 7);
      let blue = 200 - 120 * t;
      const d = Math.hypot(x - cx, y - cy);
      if (d < r) {
        red = 250 - d;
        green = 200 - d * 0.8;
        blue = 60;
      }
      if (y > height * 0.7 && Math.sin(x / 6 + y / 4) > 0.4) {
        red *= 0.55;
        green *= 0.75;
        blue *= 0.5;
      }
      const grain = (rnd() - 0.5) * 36;
      const i = (y * width + x) * 3;
      rgb[i] = clamp(red + grain);
      rgb[i + 1] = clamp(green + grain);
      rgb[i + 2] = clamp(blue + grain);
    }
  }
  return rgb;
}

/** An uncompressed 24-bit BMP (bottom-up rows, 4-byte padded) of drawPicture. */
export function makeBmp(width = 256, height = 192, seed = 7) {
  return bmpFromRgb(drawPicture(width, height, seed), width, height);
}

/** Encodes top-down RGB pixels as a 24-bit BMP. */
export function bmpFromRgb(rgb, width, height) {
  const stride = (width * 3 + 3) & ~3;
  const size = 54 + stride * height;
  const out = new Uint8Array(size);
  const dv = new DataView(out.buffer);
  out[0] = 0x42;
  out[1] = 0x4d;
  dv.setUint32(2, size, true);
  dv.setUint32(10, 54, true);
  dv.setUint32(14, 40, true);
  dv.setInt32(18, width, true);
  dv.setInt32(22, height, true);
  dv.setUint16(26, 1, true);
  dv.setUint16(28, 24, true);
  dv.setUint32(34, stride * height, true);
  dv.setInt32(38, 2835, true);
  dv.setInt32(42, 2835, true);
  for (let y = 0; y < height; y++) {
    const row = 54 + (height - 1 - y) * stride;
    for (let x = 0; x < width; x++) {
      const s = (y * width + x) * 3;
      const d = row + x * 3;
      out[d] = rgb[s + 2];
      out[d + 1] = rgb[s + 1];
      out[d + 2] = rgb[s];
    }
  }
  return out;
}

/** A binary PPM (P6) of drawPicture. */
export function makePpm(width = 256, height = 192, seed = 7) {
  return ppmFromRgb(drawPicture(width, height, seed), width, height);
}

/** Encodes top-down RGB pixels as a binary PPM. */
export function ppmFromRgb(rgb, width, height) {
  const head = new TextEncoder().encode(`P6\n${width} ${height}\n255\n`);
  const out = new Uint8Array(head.length + rgb.length);
  out.set(head, 0);
  out.set(rgb, head.length);
  return out;
}

/** Top-down RGB pixels and size of a binary PPM (P6, maxval 255, no comments). */
export function rgbFromPpm(bytes) {
  const fields = [];
  let at = 2;
  while (fields.length < 3) {
    while (bytes[at] === 0x20 || bytes[at] === 0x0a || bytes[at] === 0x0d || bytes[at] === 0x09) at++;
    let n = 0;
    while (bytes[at] >= 0x30 && bytes[at] <= 0x39) n = n * 10 + (bytes[at++] - 0x30);
    fields.push(n);
  }
  const [width, height] = fields;
  return { width, height, rgb: bytes.subarray(at + 1, at + 1 + width * height * 3) };
}

/** Top-down RGB pixels and size of an uncompressed 24-bit BMP, or null for any other BMP. */
export function rgbFromBmp(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 54 || dv.getUint16(28, true) !== 24 || dv.getUint32(30, true) !== 0) return null;
  const offset = dv.getUint32(10, true);
  const width = dv.getInt32(18, true);
  const raw = dv.getInt32(22, true);
  const height = Math.abs(raw);
  const stride = (width * 3 + 3) & ~3;
  const rgb = new Uint8Array(width * height * 3);
  for (let y = 0; y < height; y++) {
    const row = offset + (raw > 0 ? height - 1 - y : y) * stride;
    for (let x = 0; x < width; x++) {
      const s = row + x * 3;
      const d = (y * width + x) * 3;
      rgb[d] = bytes[s + 2];
      rgb[d + 1] = bytes[s + 1];
      rgb[d + 2] = bytes[s];
    }
  }
  return { width, height, rgb };
}

/** Pixels that differ between two equal-size RGB images and the largest channel change. */
export function pixelDiff(a, b) {
  let changed = 0;
  let maxDelta = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 3) {
    let moved = false;
    for (let c = 0; c < 3; c++) {
      const d = Math.abs(a[i + c] - b[i + c]);
      if (d) moved = true;
      if (d > maxDelta) maxDelta = d;
    }
    if (moved) changed++;
  }
  return { changed, total: n / 3, maxDelta };
}

/** A 16-bit mono PCM WAV at 44.1 kHz: a two-tone chord with a little noise. */
export function makeWav(seconds = 1, seed = 11) {
  const rate = 44100;
  const count = Math.round(rate * seconds);
  const out = new Uint8Array(44 + count * 2);
  const dv = new DataView(out.buffer);
  const tag = (at, text) => {
    for (let i = 0; i < 4; i++) out[at + i] = text.charCodeAt(i);
  };
  tag(0, 'RIFF');
  dv.setUint32(4, 36 + count * 2, true);
  tag(8, 'WAVE');
  tag(12, 'fmt ');
  dv.setUint32(16, 16, true);
  dv.setUint16(20, 1, true);
  dv.setUint16(22, 1, true);
  dv.setUint32(24, rate, true);
  dv.setUint32(28, rate * 2, true);
  dv.setUint16(32, 2, true);
  dv.setUint16(34, 16, true);
  tag(36, 'data');
  dv.setUint32(40, count * 2, true);
  const rnd = noise(seed);
  for (let i = 0; i < count; i++) {
    const t = i / rate;
    const fade = Math.min(1, i / 2000, (count - i) / 2000);
    const v = fade * (0.35 * Math.sin(2 * Math.PI * 440 * t) + 0.2 * Math.sin(2 * Math.PI * 660 * t))
      + (rnd() - 0.5) * 0.08;
    dv.setInt16(44 + i * 2, Math.max(-32768, Math.min(32767, Math.round(v * 32767))), true);
  }
  return out;
}

/** A file of `size` bytes that repeats `pattern` (a weak entropy source). */
export function makePattern(size, pattern = [0]) {
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) out[i] = pattern[i % pattern.length];
  return out;
}

/** 16-bit samples of the data chunk of a PCM WAV, or null when there is none. */
export function samplesFromWav(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 12;
  while (at + 8 <= bytes.length) {
    const id = String.fromCharCode(bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]);
    const size = dv.getUint32(at + 4, true);
    if (id === 'data') {
      const n = Math.floor(Math.min(size, bytes.length - at - 8) / 2);
      const out = new Int16Array(n);
      for (let i = 0; i < n; i++) out[i] = dv.getInt16(at + 8 + i * 2, true);
      return out;
    }
    at += 8 + size + (size & 1);
  }
  return null;
}

/** Samples that differ, the largest change and the signal-to-noise ratio in dB. */
export function sampleDiff(a, b) {
  let changed = 0;
  let maxDelta = 0;
  let signal = 0;
  let error = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = Math.abs(a[i] - b[i]);
    if (d) changed++;
    if (d > maxDelta) maxDelta = d;
    signal += a[i] * a[i];
    error += d * d;
  }
  return { changed, total: n, maxDelta, snr: error ? 10 * Math.log10(signal / error) : Infinity };
}

const STEGO_EXT = ['.ppm', '.bmp', '.png', '.gif', '.jpg', '.jpeg', '.wav', '.flac', '.mp3', '.crvf', '.avi', '.mp4'];

/** Lower-case extension of a file name, with the dot, or an empty string. */
export function extOf(name) {
  const at = String(name || '').lastIndexOf('.');
  return at < 0 ? '' : String(name).slice(at).toLowerCase();
}

/** The extension the engine writes for a carrier: GIF comes back as PNG, FLAC as WAV. */
export function outExt(ext) {
  if (ext === '.gif') return '.png';
  if (ext === '.flac') return '.wav';
  return ext;
}

/** The extension that matches a file's magic bytes, or an empty string. */
export function sniffExt(bytes) {
  const b = bytes;
  const tag = (at, text) => [...text].every((ch, i) => b[at + i] === ch.charCodeAt(0));
  if (b.length < 12) return '';
  if (tag(0, 'BM')) return '.bmp';
  if (b[0] === 0x89 && tag(1, 'PNG')) return '.png';
  if (tag(0, 'P6')) return '.ppm';
  if (tag(0, 'GIF8')) return '.gif';
  if (b[0] === 0xff && b[1] === 0xd8) return '.jpg';
  if (tag(0, 'RIFF') && tag(8, 'WAVE')) return '.wav';
  if (tag(0, 'RIFF') && tag(8, 'AVI ')) return '.avi';
  if (tag(0, 'fLaC')) return '.flac';
  return '';
}

/** MIME type a browser can display for an extension, or null. */
export function imageMime(ext) {
  if (ext === '.bmp') return 'image/bmp';
  if (ext === '.png') return 'image/png';
  if (ext === '.gif') return 'image/gif';
  if (ext === '.jpg' || ext === '.jpeg') return 'image/jpeg';
  return null;
}

/** MIME type for a download of a carrier with this extension. */
export function fileMime(ext) {
  if (ext === '.wav') return 'audio/wav';
  if (ext === '.ppm') return 'image/x-portable-pixmap';
  return imageMime(ext) || 'application/octet-stream';
}

/**
 * A carrier from a file input: `value` may be absent, a Uint8Array, or an object
 * with bytes (or data) and a name. Falls back to `fallback()`, which returns
 * { bytes, name }. The result carries a supported extension in `ext`.
 */
export function carrierFrom(value, fallback) {
  const raw = value instanceof Uint8Array ? value : value && (value.bytes || value.data);
  if (raw && raw.length) {
    const bytes = raw instanceof Uint8Array ? raw : new Uint8Array(raw);
    const named = extOf(value && value.name);
    const ext = STEGO_EXT.includes(named) ? named : sniffExt(bytes);
    if (ext) return { bytes, name: (value && value.name) || `upload${ext}`, ext, uploaded: true };
  }
  const made = fallback();
  return { ...made, ext: extOf(made.name), uploaded: false };
}

/** Top-down RGB pixels of a BMP or PPM carrier, or null for other formats. */
export function pixelsOf(bytes, ext) {
  if (ext === '.bmp') return rgbFromBmp(bytes);
  if (ext === '.ppm') return rgbFromPpm(bytes);
  return null;
}

/** Text with typographic dashes and other non-ASCII characters made plain. */
export function plain(text) {
  return String(text ?? '').replace(/[\u2012-\u2015]/g, '-').replace(/[\u2192]/g, '->').replace(/[^\x09\x0a\x20-\x7e]/g, '?');
}

/** Paths under `dir` in the engine's file system, removed again by clean(). */
export function workspace(cb, dir) {
  const used = new Set();
  const path = (name) => {
    const p = `${dir}/${name}`;
    used.add(p);
    return p;
  };
  return {
    path,
    put(name, bytes) {
      const p = path(name);
      cb.writeFile(p, bytes);
      return p;
    },
    clean() {
      const fs = cb.engine.module.FS;
      for (const p of used) {
        try {
          fs.unlink(p);
        } catch (error) {
          used.delete(p);
        }
      }
      used.clear();
    },
  };
}
