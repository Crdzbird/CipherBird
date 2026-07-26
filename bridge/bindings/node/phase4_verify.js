// Verifies the Phase 1-4 stego/FEC/analysis bindings through koffi.
//   node phase4_verify.js [path-to-libcryptolib_c.dylib]
// Exits non-zero on any failure.
'use strict';
const koffi = require('koffi');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const libPath = process.argv[2] || 'build/release/libcryptolib_c.dylib';
const lib = koffi.load(libPath);

const CryptoBuffer = koffi.struct('CryptoBuffer', { data: 'void *', len: 'size_t' });
const CryptoBufferResult = koffi.struct('CryptoBufferResult', { buf: CryptoBuffer, error: 'void *' });
const CryptoResult = koffi.struct('CryptoResult', { ok: 'int', error: 'void *' });
const CryptoFileInspection = koffi.struct('CryptoFileInspection', {
  parses: 'int', format: 'uint8', ext_matches: 'int',
  width: 'uint64_t', height: 'uint64_t', file_size: 'uint64_t',
  detail: 'void *', error: 'void *',
});
const CryptoHiddenDataReport = koffi.struct('CryptoHiddenDataReport', {
  cryptolib_payload: 'int', lsb_chi_square: 'double',
  lsb_embedding_likelihood: 'double', samples_analysed: 'uint64_t',
  note: 'void *', error: 'void *',
});

const init = lib.func('int cryptolib_init()');
const strFree = lib.func('void cryptolib_str_free(void *s)');
const bufFree = lib.func('void cryptolib_buffer_free(CryptoBuffer *buf)');
const f = {
  embedKeyed: lib.func('CryptoResult cryptolib_stego_embed_keyed(const char*, uint8_t*, size_t, const char*, uint8_t*, size_t)'),
  extractKeyed: lib.func('CryptoBufferResult cryptolib_stego_extract_keyed(const char*, uint8_t*, size_t)'),
  embedEnc: lib.func('CryptoResult cryptolib_stego_embed_encrypted(const char*, uint8_t*, size_t, const char*, uint8_t*, size_t)'),
  extractDec: lib.func('CryptoBufferResult cryptolib_stego_extract_decrypt(const char*, uint8_t*, size_t)'),
  physSeal: lib.func('CryptoResult cryptolib_physical_seal(const char*, uint8_t*, size_t, uint8_t*, size_t, const char*, const char*)'),
  physOpen: lib.func('CryptoBufferResult cryptolib_physical_open(const char*, uint8_t*, size_t, const char*)'),
  fecEncode: lib.func('CryptoBufferResult cryptolib_fec_encode(uint8_t*, size_t, int)'),
  fecDecode: lib.func('CryptoBufferResult cryptolib_fec_decode(uint8_t*, size_t, int, size_t)'),
  inspect: lib.func('CryptoFileInspection cryptolib_stego_inspect(const char*)'),
  digest: lib.func('CryptoBufferResult cryptolib_stego_content_digest(const char*)'),
  detect: lib.func('CryptoHiddenDataReport cryptolib_stego_detect_hidden(const char*)'),
};

let failures = 0;
function check(ok, label) {
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label}`);
  if (!ok) failures++;
}
// Mirror demo.js: inspect buf first; on error free the string pointer and
// return an empty Buffer (callers treat empty as failure). Avoids decoding the
// error pointer (the koffi char*-as-void* free gotcha).
function consume(res) {
  if (!res.buf.data || Number(res.buf.len) === 0) {
    if (res.error) strFree(res.error);
    return Buffer.alloc(0);
  }
  const n = Number(res.buf.len);
  const out = Buffer.from(koffi.decode(res.buf.data, 'uint8_t', n));
  bufFree(res.buf);
  return out;
}
function checkResult(r) { if (r.ok === 0) { if (r.error) strFree(r.error); throw new Error('C call failed'); } }

function noisePpm(p, w, h, seed) {
  const head = Buffer.from(`P6\n${w} ${h}\n255\n`);
  const body = Buffer.alloc(w * h * 3);
  let s = seed >>> 0;
  for (let i = 0; i < body.length; i++) { s ^= (s << 13); s ^= (s >>> 17); s ^= (s << 5); body[i] = s & 0xFF; }
  fs.writeFileSync(p, Buffer.concat([head, body]));
}

if (init() !== 0) throw new Error('init failed');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cl_p4_node_'));
const key = Buffer.alloc(32, 0x5a);

// 1. Keyed stego
{
  const cover = path.join(dir, 'c1.ppm'), out = path.join(dir, 'o1.ppm');
  noisePpm(cover, 256, 256, 0xC0FFEE);
  const payload = Buffer.from('keyed stego via Node');
  checkResult(f.embedKeyed(cover, payload, payload.length, out, key, key.length));
  const got = consume(f.extractKeyed(out, key, key.length));
  check(got.equals(payload), 'keyed stego round-trip');
  const bad = consume(f.extractKeyed(out, Buffer.alloc(32, 0x99), 32));
  check(bad.length === 0, 'keyed stego wrong-key rejected');
}

// 2. Always-encrypt
{
  const cover = path.join(dir, 'c2.ppm'), out = path.join(dir, 'o2.ppm');
  noisePpm(cover, 256, 256, 0xBEEF);
  const secret = Buffer.from('never in the clear');
  checkResult(f.embedEnc(cover, secret, secret.length, out, key, key.length));
  const got = consume(f.extractDec(out, key, key.length));
  check(got.equals(secret), 'always-encrypt round-trip');
}

// 3. PhysicalSeal
{
  const km = path.join(dir, 'k3.ppm'), cover = path.join(dir, 'c3.ppm'), out = path.join(dir, 'o3.ppm');
  noisePpm(km, 64, 64, 0xABCDEF); noisePpm(cover, 256, 256, 0x123456);
  const msg = Buffer.from('the photo is the key'), aad = Buffer.from('node-ctx');
  checkResult(f.physSeal(km, msg, msg.length, aad, aad.length, cover, out));
  const got = consume(f.physOpen(km, aad, aad.length, out));
  check(got.equals(msg), 'PhysicalSeal round-trip');
}

// 4. FEC single-flip
{
  const data = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]);
  for (const scheme of [1, 2, 3]) {
    const enc = consume(f.fecEncode(data, data.length, scheme));
    enc[0] ^= 0x40;
    const dec = consume(f.fecDecode(enc, enc.length, scheme, data.length));
    check(dec.equals(data), `FEC scheme ${scheme} corrects a single flip`);
  }
}

// 5. Analysis: validity + tamper digest + hidden-data probe
{
  const cover = path.join(dir, 'a.ppm'), stego = path.join(dir, 'as.ppm');
  noisePpm(cover, 128, 128, 0x99);
  const insp = f.inspect(cover);
  check(insp.error === null && insp.parses !== 0 && insp.ext_matches !== 0 && Number(insp.width) === 128, 'inspect valid PPM');
  if (insp.detail) strFree(insp.detail);

  const d1 = consume(f.digest(cover));
  fs.appendFileSync(cover, Buffer.from([0]));
  const d2 = consume(f.digest(cover));
  check(!d1.equals(d2), 'content digest changes on tamper');

  noisePpm(cover, 128, 128, 0x99);
  const embed = lib.func('CryptoResult cryptolib_stego_embed(const char*, uint8_t*, size_t, const char*)');
  checkResult(embed(cover, Buffer.from('hi'), 2, stego));
  const rep = f.detect(stego);
  // note/error are char* stored as void*; read with koffi.decode(ptr,'char',N)
  // (decoding as 'char *' would double-dereference and crash).
  const note = rep.note ? koffi.decode(rep.note, 'char', 512) : '';
  check(rep.error === null && rep.cryptolib_payload !== 0 && note.length > 0, 'detect unkeyed payload + note');
  if (rep.note) strFree(rep.note);
}

fs.rmSync(dir, { recursive: true, force: true });
console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
