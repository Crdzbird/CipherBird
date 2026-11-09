/*
 * PASETO v4.local and the cb1 tokens through the Node binding: round trips,
 * fail-closed verification, the official PASETO vectors and the pinned cb1
 * vectors shared with every binding, plus keyed BLAKE2b.
 *
 * CIPHERBIRD_LIBRARY=<path> node test/tokens.js
 */
'use strict';
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const c = require('..');

let pass = 0;
const ok = (label, f) => { f(); pass++; console.log(`  ok  ${label}`); };
const B = (s) => Buffer.from(s);
const counting = (n, start) => Buffer.from(Array.from({ length: n }, (_, i) => (start + i) & 0xff));
const key = counting(32, 0x70);
const other = counting(32, 0x90);
const vectorsDir = path.join(__dirname, '..', '..', '..', '..', 'tests', 'vectors');

ok('PASETO v4.local round trips, shape and exact length', () => {
  for (const [m, f, i] of [[B(''), null, null], [B('{"data":"x"}'), null, null], [B('{"data":"x"}'), B('{"kid":"a"}'), null],
    [B('{"data":"x"}'), null, B('ctx')], [Buffer.alloc(1000, 0xff), B('f'), B('i')]]) {
    const tok = c.pasetoV4LocalEncrypt(key, m, f, i);
    assert.ok(tok.startsWith('v4.local.'));
    assert.strictEqual(tok.length, c.Paseto.v4LocalEncryptLen(m.length, f ? f.length : 0));
    assert.strictEqual((tok.match(/\./g) || []).length, f ? 3 : 2);
    assert.ok(c.pasetoV4LocalDecrypt(tok, key, f, i).equals(m));
  }
  assert.notStrictEqual(c.pasetoV4LocalEncrypt(key, B('m')), c.pasetoV4LocalEncrypt(key, B('m')));
});

ok('PASETO v4.local fails closed on every tampered byte and mismatch', () => {
  const f = B('{"kid":"k"}'), i = B('bind');
  const tok = c.pasetoV4LocalEncrypt(key, B('{"data":"x"}'), f, i);
  for (let pos = 0; pos < tok.length; pos++) {
    const sub = tok[pos] === 'A' ? 'B' : 'A';
    const x = tok.slice(0, pos) + sub + tok.slice(pos + 1);
    assert.throws(() => c.pasetoV4LocalDecrypt(x, key, f, i), /invalid PASETO/);
  }
  assert.throws(() => c.pasetoV4LocalDecrypt(tok, other, f, i), /invalid/);
  assert.throws(() => c.pasetoV4LocalDecrypt(tok, key, B('g'), i), /invalid/);
  assert.throws(() => c.pasetoV4LocalDecrypt(tok, key, f, null), /invalid/);
  assert.throws(() => c.pasetoV4LocalDecrypt(`${tok}=`, key, f, i), /invalid/);
  assert.throws(() => c.pasetoV4LocalDecrypt('', key), /invalid/);
  assert.throws(() => c.pasetoV4LocalEncrypt(key.subarray(0, 31), B('m')), RangeError);
  assert.throws(() => c.pasetoV4LocalDecrypt(tok, key.subarray(0, 31), f, i), RangeError);
});

ok('the official PASETO v4 vectors decrypt and the failure vectors are rejected', () => {
  const file = path.join(vectorsDir, 'paseto', 'v4.json');
  if (!fs.existsSync(file)) { console.log('      (vectors not present, skipped)'); return; }
  const { tests } = JSON.parse(fs.readFileSync(file, 'utf8'));
  let decrypted = 0, rejected = 0;
  for (const t of tests) {
    if (t.name === '4-F-1' || !/^4-[EF]-/.test(t.name)) continue;
    const k = Buffer.from(t.key, 'hex');
    const footer = t.footer ? B(t.footer) : null;
    const implicit = t['implicit-assertion'] ? B(t['implicit-assertion']) : null;
    if (t['expect-fail']) { assert.throws(() => c.pasetoV4LocalDecrypt(t.token, k, footer, implicit), /invalid/); rejected++; continue; }
    assert.strictEqual(c.pasetoV4LocalDecrypt(t.token, k, footer, implicit).toString(), t.payload, t.name);
    decrypted++;
  }
  assert.strictEqual(decrypted, 9);
  assert.strictEqual(rejected, 4);
});

ok('cb1.local round trips and rejects PASETO, and vice versa', () => {
  for (const [m, f, i] of [[B(''), null, null], [B('{"data":"x"}'), B('{"kid":"a"}'), B('ctx')], [Buffer.alloc(1 << 16, 0x5a), B('f'), null]]) {
    const tok = c.cb1LocalEncrypt(key, m, f, i);
    assert.ok(tok.startsWith('cb1.local.'));
    assert.strictEqual(tok.length, c.Cb1.localEncryptLen(m.length, f ? f.length : 0));
    assert.ok(c.cb1LocalDecrypt(tok, key, f, i).equals(m));
    assert.throws(() => c.cb1LocalDecrypt(tok, other, f, i), /invalid cb1/);
  }
  const v4 = c.pasetoV4LocalEncrypt(key, B('m'));
  assert.throws(() => c.cb1LocalDecrypt(v4, key), /invalid cb1/);
  const cb = c.cb1LocalEncrypt(key, B('m'));
  assert.throws(() => c.pasetoV4LocalDecrypt(cb, key), /invalid PASETO/);
  const tok = c.cb1LocalEncrypt(key, B('{"data":"x"}'), B('f'), B('i'));
  for (let pos = 0; pos < tok.length; pos++) {
    const sub = tok[pos] === 'A' ? 'B' : 'A';
    assert.throws(() => c.cb1LocalDecrypt(tok.slice(0, pos) + sub + tok.slice(pos + 1), key, B('f'), B('i')), /invalid/);
  }
});

ok('cb1.public signs with the hybrid key and both halves are required', () => {
  const kp = c.hybridSigKeygen();
  const stranger = c.hybridSigKeygen();
  assert.strictEqual(kp.publicKey.length, c.Cb1.PUBLIC_KEY_BYTES);
  assert.strictEqual(kp.secretKey.length, c.Cb1.SECRET_KEY_BYTES);
  const m = B('{"sub":"alice"}'), f = B('{"kid":"k1"}'), i = B('aud');
  const tok = c.cb1PublicSign(kp.secretKey, m, f, i);
  assert.ok(tok.startsWith('cb1.public.'));
  assert.strictEqual(tok.length, c.Cb1.publicSignLen(m.length, f.length));
  assert.ok(c.cb1PublicVerify(tok, kp.publicKey, f, i).equals(m));
  assert.throws(() => c.cb1PublicVerify(tok, stranger.publicKey, f, i), /invalid cb1/);
  assert.throws(() => c.cb1PublicVerify(tok, kp.publicKey, B('g'), i), /invalid/);
  assert.throws(() => c.cb1PublicVerify(tok, kp.publicKey, f, null), /invalid/);
  const raw = Buffer.from(tok.slice(11, tok.indexOf('.', 11)), 'base64url');
  assert.strictEqual(raw.length, m.length + c.Cb1.SIGNATURE_BYTES);
  for (const pos of [0, m.length, m.length + 63, m.length + 64, raw.length - 1]) {
    const x = Buffer.from(raw); x[pos] ^= 1;
    assert.throws(() => c.cb1PublicVerify(`cb1.public.${x.toString('base64url')}.${f.toString('base64url')}`, kp.publicKey, f, i), /invalid/);
  }
  assert.throws(() => c.cb1PublicSign(kp.secretKey.subarray(0, 64), m), RangeError);
});

ok('the pinned cb1 vectors decrypt and verify', () => {
  const file = path.join(vectorsDir, 'cb1', 'vectors.json');
  if (!fs.existsSync(file)) { console.log('      (vectors not present, skipped)'); return; }
  const v = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.ok(v.local.length >= 10 && v.public.length >= 8);
  for (const t of v.local) {
    const k = Buffer.from(t.key, 'hex');
    const footer = t.footer ? B(t.footer) : null, implicit = t['implicit-assertion'] ? B(t['implicit-assertion']) : null;
    if (t['expect-fail']) { assert.throws(() => c.cb1LocalDecrypt(t.token, k, footer, implicit), /invalid/, t.name); continue; }
    assert.strictEqual(c.cb1LocalDecrypt(t.token, k, footer, implicit).toString(), t.payload, t.name);
  }
  for (const t of v.public) {
    const pk = Buffer.from(t['public-key'], 'hex'), sk = Buffer.from(t['secret-key'], 'hex');
    const footer = t.footer ? B(t.footer) : null, implicit = t['implicit-assertion'] ? B(t['implicit-assertion']) : null;
    if (t['expect-fail']) { assert.throws(() => c.cb1PublicVerify(t.token, pk, footer, implicit), /invalid/, t.name); continue; }
    assert.strictEqual(c.cb1PublicVerify(t.token, pk, footer, implicit).toString(), t.payload, t.name);
    const again = c.cb1PublicSign(sk, B(t.payload), footer, implicit);
    assert.strictEqual(c.cb1PublicVerify(again, pk, footer, implicit).toString(), t.payload, t.name);
  }
});

ok('the generic token table lists every format with its sizes', () => {
  const formats = c.tokenFormats();
  assert.deepStrictEqual(formats.map((f) => f.format).sort(), ['cb1.local', 'cb1.public', 'v4.local']);
  for (const f of formats) {
    assert.strictEqual(f.purpose, f.format.endsWith('.public') ? 'public' : 'local');
    assert.strictEqual(f.max_input_bytes, 1 << 26);
    assert.strictEqual(f.available, c.Tokens.issueLen(f.format, 1) !== 0);
    if (f.purpose === 'local') assert.strictEqual(f.key_bytes, 32);
    else assert.deepStrictEqual([f.public_key_bytes, f.secret_key_bytes, f.signature_bytes], [1984, 4096, 3373]);
  }
  assert.ok(formats.find((f) => f.format === 'v4.local').available);
  assert.strictEqual(c.tokens.formats().length, formats.length);
});

ok('unknown formats and unavailable formats are told apart', () => {
  assert.throws(() => c.tokenIssue('v9.local', key, B('m')), /unknown token format/);
  assert.throws(() => c.tokenAccept('v9.local', 'v9.local.AAAA', key), /unknown token format/);
  assert.throws(() => c.tokenKeygen('v4.secret'), /unknown token format/);
  assert.strictEqual(c.Tokens.issueLen('v9.local', 1), 0);
  for (const f of c.tokenFormats()) {
    if (f.available) continue;
    assert.throws(() => c.tokenIssue(f.format, key, B('m')), /not available/);
    assert.throws(() => c.tokenKeygen(f.format), /not available/);
    console.log(`      ${f.format} is not in this profile: reports unavailable`);
  }
});

ok('keygen, issue and accept round-trip in every available format', () => {
  for (const f of c.tokenFormats()) {
    if (!f.available) continue;
    const k = c.tokenKeygen(f.format);
    const acceptKey = f.purpose === 'public' ? k.publicKey : k.secretKey;
    if (f.purpose === 'public') assert.deepStrictEqual([k.secretKey.length, k.publicKey.length], [4096, 1984]);
    else { assert.strictEqual(k.secretKey.length, 32); assert.strictEqual(k.publicKey, null); }
    const m = B('{"sub":"alice"}'), footer = B('{"kid":"k1"}'), implicit = B('audience');
    const tok = c.tokenIssue(f.format, k.secretKey, m, footer, implicit);
    assert.ok(tok.startsWith(`${f.format}.`));
    assert.strictEqual(tok.length, c.Tokens.issueLen(f.format, m.length, footer.length));
    assert.ok(c.tokenAccept(f.format, tok, acceptKey, footer, implicit).equals(m));
    assert.ok(c.tokens.accept(f.format, tok, acceptKey, footer, implicit).equals(m));
    assert.throws(() => c.tokenAccept(f.format, tok, acceptKey, B('{"kid":"k2"}'), implicit), /invalid/);
    assert.throws(() => c.tokenAccept(f.format, tok, acceptKey, footer, null), /invalid/);
    const flipped = tok.slice(0, -1) + (tok.endsWith('A') ? 'B' : 'A');
    assert.throws(() => c.tokenAccept(f.format, flipped, acceptKey, footer, implicit), /invalid/);
    const other = c.tokenKeygen(f.format);
    assert.throws(() => c.tokenAccept(f.format, tok, f.purpose === 'public' ? other.publicKey : other.secretKey, footer, implicit), /invalid/);
    assert.throws(() => c.tokenIssue(f.format, k.secretKey.subarray(1), m), RangeError);
    assert.strictEqual(c.tokenPeekFormat(tok), f.format);
    assert.ok(c.tokenPeekFooter(tok).equals(footer));
    const bare = c.tokenIssue(f.format, k.secretKey, B(''));
    assert.strictEqual((bare.match(/\./g) || []).length, 2);
    assert.strictEqual(c.tokenPeekFooter(bare), null);
    assert.strictEqual(c.tokenAccept(f.format, bare, acceptKey).length, 0);
  }
});

ok('the caller names the format and the header never chooses', () => {
  const v4 = c.tokenIssue('v4.local', key, B('m'));
  assert.throws(() => c.tokenAccept('v4.local', `cb1.local.${v4.slice('v4.local.'.length)}`, key), /invalid/);
  if (c.tokenFormats().find((f) => f.format === 'cb1.local').available) {
    const cb1 = c.tokenIssue('cb1.local', key, B('m'));
    assert.throws(() => c.tokenAccept('v4.local', cb1, key), /invalid/);
    assert.throws(() => c.tokenAccept('cb1.local', v4, key), /invalid/);
    assert.ok(c.tokenAccept('cb1.local', cb1, key).equals(B('m')));
    assert.ok(c.cb1LocalDecrypt(cb1, key).equals(B('m')));
    assert.ok(c.tokenAccept('cb1.local', c.cb1LocalEncrypt(key, B('m')), key).equals(B('m')));
  }
  assert.ok(c.pasetoV4LocalDecrypt(v4, key).equals(B('m')));
  assert.strictEqual(c.tokenPeekFormat('v9.public.abc'), 'v9.public');
  assert.strictEqual(c.tokenPeekFormat('v4.secret.abc'), '');
  assert.strictEqual(c.tokenPeekFormat(''), '');
  assert.throws(() => c.tokenPeekFooter('v4.local.abc.a=b'), /invalid/);
  assert.throws(() => c.tokenPeekFooter('nonsense'), /invalid/);
  assert.strictEqual(c.tokenPeekFooter('v4.local.abc.a2lk').toString(), 'kid');
});

ok('the common-schema vectors accept through the generic calls', () => {
  const dir = path.join(vectorsDir, 'tokens');
  if (!fs.existsSync(dir)) { console.log('      (vectors not present, skipped)'); return; }
  const files = fs.readdirSync(dir).filter((n) => n.endsWith('.json'));
  assert.ok(files.length >= 3);
  const table = c.tokenFormats();
  for (const name of files) {
    const v = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
    assert.strictEqual(`${v.format}.json`, name);
    assert.ok(v.cases.length > 0);
    const f = table.find((x) => x.format === v.format);
    assert.ok(f, v.format);
    if (!f.available) { console.log(`      ${v.format}: not in this profile, skipped`); continue; }
    const pub = f.purpose === 'public';
    let pass = 0, fail = 0;
    for (const t of v.cases) {
      const keyHex = pub ? t['public-key'] : t.key;
      const footer = t.footer ? B(t.footer) : null, implicit = t['implicit-assertion'] ? B(t['implicit-assertion']) : null;
      if (!keyHex) { assert.ok(t['expect-fail'], t.name); fail++; continue; }
      const k = Buffer.from(keyHex, 'hex');
      if (t['expect-fail']) { assert.throws(() => c.tokenAccept(v.format, t.token, k, footer, implicit), /invalid/, t.name); fail++; continue; }
      assert.strictEqual(c.tokenAccept(v.format, t.token, k, footer, implicit).toString(), t.payload, t.name);
      assert.strictEqual(c.tokenPeekFormat(t.token), v.format);
      assert.strictEqual((c.tokenPeekFooter(t.token) || B('')).toString(), t.footer);
      if (pub) {
        const again = c.tokenIssue(v.format, Buffer.from(t['secret-key'], 'hex'), B(t.payload), footer, implicit);
        assert.strictEqual(c.tokenAccept(v.format, again, k, footer, implicit).toString(), t.payload, t.name);
      }
      pass++;
    }
    console.log(`      ${v.format}: ${pass} accepted, ${fail} rejected as expected`);
  }
});

ok('keyed BLAKE2b matches the libsodium known answers, allocating or into a buffer', () => {
  assert.strictEqual(c.blake2bKeyed(counting(31, 0), counting(32, 0), 32).toString('hex'), 'a9f51bb7f6a3e9cdb96ce652c07d177962a348a9cced1b92f948187e59b44463');
  assert.strictEqual(c.blake2bKeyed(B('abc'), null, 32).toString('hex'), 'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319');
  assert.strictEqual(c.blake2bKeyed(B('abc'), null, 1).toString('hex'), '6b');
  const out = Buffer.alloc(32);
  assert.strictEqual(c.blake2bKeyedInto(out, counting(31, 0), counting(32, 0)), out);
  assert.strictEqual(out.toString('hex'), 'a9f51bb7f6a3e9cdb96ce652c07d177962a348a9cced1b92f948187e59b44463');
  assert.throws(() => c.blake2bKeyed(B('m'), counting(15, 0), 32));
  assert.throws(() => c.blake2bKeyedInto(Buffer.alloc(65), B('m')), RangeError);
  assert.strictEqual(c.hash.blake2bKeyed(B('abc'), null, { outLen: 1 }).toString('hex'), '6b');
});

ok('the tokens namespace and the worker reach the same functions', () => {
  const tok = c.tokens.v4LocalEncrypt(key, B('ns'));
  assert.strictEqual(c.tokens.v4LocalDecrypt(tok, key).toString(), 'ns');
  assert.strictEqual(c.tokens.cb1.localDecrypt(c.tokens.cb1LocalEncrypt(key, B('cb')), key).toString(), 'cb');
});

(async () => {
  const kp = c.hybridSigKeygen();
  const tok = await c.async.cb1PublicSign(kp.secretKey, B('async'));
  assert.strictEqual((await c.async.cb1PublicVerify(tok, kp.publicKey)).toString(), 'async');
  pass++;
  console.log('  ok  cb1.public signs and verifies on the worker thread');
  await c.async.close();
  console.log(`\ncipherbird tokens: OK (${pass} passed)`);
})().catch((e) => { console.error('FAILED:', e); process.exit(1); });
