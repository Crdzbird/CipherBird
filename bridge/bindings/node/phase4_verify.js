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

// 6. ImageFactorSeal (C2)
{
  const ifSeal = lib.func('CryptoResult cryptolib_image_factor_seal(uint8_t*, size_t, const char*, uint8_t*, size_t, uint8_t*, size_t, const char*, const char*)');
  const ifOpen = lib.func('CryptoBufferResult cryptolib_image_factor_open(uint8_t*, size_t, const char*, uint8_t*, size_t, const char*)');
  const img = path.join(dir, 'ref.ppm'), cover = path.join(dir, 'ifs_cover.ppm'), out = path.join(dir, 'ifs_out.ppm');
  noisePpm(img, 64, 64, 0xFEED); noisePpm(cover, 256, 256, 0xCAFE);
  const seed = Buffer.alloc(32, 0x42);
  const msg = Buffer.from('image is the second factor');
  checkResult(ifSeal(seed, seed.length, img, msg, msg.length, null, 0, cover, out));
  const got = consume(ifOpen(seed, seed.length, img, null, 0, out));
  check(got.equals(msg), 'ImageFactorSeal round-trip');
  const other = path.join(dir, 'ref2.ppm'); noisePpm(other, 64, 64, 0xBEEF);
  check(consume(ifOpen(seed, seed.length, other, null, 0, out)).length === 0, 'ImageFactorSeal wrong-image rejected');
}

// 7. HpkeStegoSeal (C3)
{
  const CryptoKeyPair = koffi.struct('CryptoKeyPair', { public_key: CryptoBuffer, secret_key: CryptoBuffer });
  const hpkeKeygen = lib.func('CryptoKeyPair cryptolib_hpke_keygen()');
  const kpFree = lib.func('void cryptolib_keypair_free(CryptoKeyPair* kp)');
  const hsSeal = lib.func('CryptoBufferResult cryptolib_hpke_stego_seal(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const char*, const char*)');
  const hsOpen = lib.func('CryptoBufferResult cryptolib_hpke_stego_open(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const char*)');
  const kpBytes = (b) => Buffer.from(koffi.decode(b.data, 'uint8_t', Number(b.len)));
  const cover = path.join(dir, 'hss_cover.ppm'), out = path.join(dir, 'hss_out.ppm');
  noisePpm(cover, 256, 256, 0x4321);
  const kp = hpkeKeygen();
  const pk = kpBytes(kp.public_key), sk = kpBytes(kp.secret_key);
  kpFree(kp);
  const info = Buffer.from('session'), msg = Buffer.from('one session keys both');
  const enc = consume(hsSeal(pk, pk.length, msg, msg.length, null, 0, info, info.length, cover, out));
  const got = consume(hsOpen(sk, sk.length, enc, enc.length, null, 0, info, info.length, out));
  check(got.equals(msg), 'HpkeStegoSeal round-trip');
  const kp2 = hpkeKeygen(); const sk2 = kpBytes(kp2.secret_key); kpFree(kp2);
  check(consume(hsOpen(sk2, sk2.length, enc, enc.length, null, 0, info, info.length, out)).length === 0, 'HpkeStegoSeal wrong-recipient rejected');
}

// 8. HMAC-DRBG handle (A3)
{
  const drbgNew = lib.func('void* cryptolib_drbg_instantiate(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, _Out_ char**)');
  const drbgGen = lib.func('CryptoBufferResult cryptolib_drbg_generate(void*, size_t, uint8_t*, size_t)');
  const drbgFree = lib.func('void cryptolib_drbg_free(void*)');
  const seed = Buffer.alloc(32, 0x01), perso = Buffer.from('beacon');
  const e1 = [null];
  const h1 = drbgNew(seed, seed.length, null, 0, perso, perso.length, e1);
  const a = consume(drbgGen(h1, 64, null, 0));
  const b = consume(drbgGen(h1, 64, null, 0));
  check(!a.equals(b), 'DRBG successive blocks differ');
  const e2 = [null];
  const h2 = drbgNew(seed, seed.length, null, 0, perso, perso.length, e2);
  check(a.equals(consume(drbgGen(h2, 64, null, 0))), 'DRBG reproducible from same seed');
  drbgFree(h1); drbgFree(h2);
  const e3 = [null];
  const bad = drbgNew(Buffer.from([1, 2, 3]), 3, null, 0, null, 0, e3);
  // koffi decodes `_Out_ char**` to a JS string (not a pointer), so it must NOT
  // be str_free'd here.
  check(!bad && e3[0] !== null, 'DRBG short-entropy rejected');
}

// 9. Fortuna handle (A5)
{
  const fNew = lib.func('void* cryptolib_fortuna_new()');
  const fAdd = lib.func('void cryptolib_fortuna_add_entropy(void*, uint8, uint8_t*, size_t)');
  const fGen = lib.func('CryptoBufferResult cryptolib_fortuna_generate(void*, size_t)');
  const fReseed = lib.func('void cryptolib_fortuna_reseed(void*)');
  const fCount = lib.func('uint64_t cryptolib_fortuna_reseed_count(void*)');
  const fFree = lib.func('void cryptolib_fortuna_free(void*)');
  const h = fNew();
  check(consume(fGen(h, 32)).length === 0, 'Fortuna unseeded generate rejected');
  for (let i = 0; i < 40; i++) { const d = Buffer.alloc(16, i); fAdd(h, i & 7, d, d.length); }
  fReseed(h);
  check(Number(fCount(h)) >= 1, 'Fortuna reseed count advances');
  check(consume(fGen(h, 64)).length === 64, 'Fortuna generate after seeding');
  fFree(h);
}

// 10. assess_file_health (A1)
{
  const CryptoHealthReport = koffi.struct('CryptoHealthReport', {
    min_entropy_per_byte: 'double', longest_run: 'uint64_t', max_window_count: 'uint64_t',
    rct_passed: 'int', apt_passed: 'int', error: 'void *',
  });
  const assess = lib.func('CryptoHealthReport cryptolib_entropy_assess_file_health(const char*, size_t)');
  const good = path.join(dir, 'good.ppm'); noisePpm(good, 128, 128, 0x1357);
  const h = assess(good, 0);
  const healthy = h.error === null && h.min_entropy_per_byte > 1.0 && h.rct_passed !== 0 && h.apt_passed !== 0;
  check(healthy, 'assess_file_health: noise carrier healthy');
  const flat = path.join(dir, 'flat.ppm');
  fs.writeFileSync(flat, Buffer.concat([Buffer.from('P6\n64 64\n255\n'), Buffer.alloc(64 * 64 * 3)]));
  const hf = assess(flat, 0);
  check(!(hf.min_entropy_per_byte >= 1.0 && hf.rct_passed !== 0 && hf.apt_passed !== 0), 'assess_file_health: constant carrier flagged');
}

fs.rmSync(dir, { recursive: true, force: true });
console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
