/*
 * P-256 ECDSA with SHA-256 through the Node binding: the RFC 6979 A.2.5
 * answers and the NIST CAVP verification cases shared with the C++, Go and
 * Dart suites, round trips, the refusal of non-canonical input, and the
 * strict PKCS#8 import of a key the OpenSSL command line wrote.
 *
 * CIPHERBIRD_LIBRARY=<path> node test/p256.js
 */
'use strict';
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const c = require('..');

let pass = 0;
const ok = (label, f) => { f(); pass++; console.log(`  ok  ${label}`); };
const hex = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p.length % 2 ? `0${p}` : p, 'hex')));
const point = (qx, qy) => Buffer.concat([Buffer.from([4]), hex(qx, qy)]);
const vectorFile = path.join(__dirname, '..', '..', '..', '..', 'tests', 'vectors', 'p256', 'ecdsa_p256_sha256.json');
const PEM = '-----BEGIN PRIVATE KEY-----\n' +
  'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgY+CswOufc3tZq8lE\n' +
  'Po6kGO5zjOLzF/kscuSONqd1FHahRANCAASkcmg2wgIEinXnLanT48k0734kS7Ut\n' +
  '5+QWxsgXYKuevjC+TcBfa1F69FCJtY7mWuNQ49vGHtWSoxIREPo4V3fY\n' +
  '-----END PRIVATE KEY-----\n';
const PEM_SK = '63e0acc0eb9f737b59abc9443e8ea418ee738ce2f317f92c72e48e36a7751476';

if (!c.p256Available()) {
  console.log('  P-256 is not in this engine: skipped');
  console.log('\ncipherbird p256: OK (0 passed)');
  process.exit(0);
}

ok('round trip, shapes and the refusal of a wrong message, key or signature', () => {
  const k = c.p256GenerateKey();
  assert.deepStrictEqual([k.secretKey.length, k.publicKey.length, k.publicKey[0]], [32, 65, 4]);
  assert.ok(c.p256PublicKey(k.secretKey).equals(k.publicKey));
  for (const m of [null, Buffer.from('m'), Buffer.alloc(100000, 7)]) {
    const s = c.p256Sign(k.secretKey, m);
    assert.strictEqual(s.length, 64);
    assert.ok(c.p256Verify(k.publicKey, m, s));
    assert.ok(!c.p256Verify(k.publicKey, Buffer.from('other'), s));
    assert.ok(!c.p256Verify(c.p256GenerateKey().publicKey, m, s));
    assert.ok(!c.p256Verify(k.publicKey, m, s.subarray(0, 63)));
    assert.ok(!c.p256Verify(k.publicKey.subarray(1), m, s));
  }
  assert.throws(() => c.p256Sign(Buffer.alloc(32), Buffer.from('m')), /out of range/);
  assert.throws(() => c.p256PublicKey(Buffer.alloc(31, 1)), /32 bytes/);
});

ok('node:crypto verifies a cipherbird signature and the reverse', () => {
  const k = c.p256GenerateKey();
  const msg = Buffer.from('header.claims');
  const pub = crypto.createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: k.publicKey.subarray(1, 33).toString('base64url'), y: k.publicKey.subarray(33).toString('base64url') } });
  assert.ok(crypto.verify('sha256', msg, { key: pub, dsaEncoding: 'ieee-p1363' }, c.p256Sign(k.secretKey, msg)));
  const theirs = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = theirs.publicKey.export({ format: 'jwk' });
  const theirPub = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const sig = crypto.sign('sha256', msg, { key: theirs.privateKey, dsaEncoding: 'ieee-p1363' });
  assert.ok(c.p256Verify(theirPub, msg, sig));
  const imported = c.p256PrivateKeyFromPkcs8(theirs.privateKey.export({ format: 'der', type: 'pkcs8' }));
  assert.ok(imported.publicKey.equals(theirPub));
  assert.ok(c.p256PrivateKeyFromPem(theirs.privateKey.export({ format: 'pem', type: 'pkcs8' })).secretKey.equals(imported.secretKey));
});

ok('the shared vectors: RFC 6979 A.2.5 and the CAVP verification cases', () => {
  if (!fs.existsSync(vectorFile)) { console.log('      (vectors not present, skipped)'); return; }
  const v = JSON.parse(fs.readFileSync(vectorFile, 'utf8'));
  const d = hex(v.rfc6979.d), q = point(v.rfc6979.qx, v.rfc6979.qy);
  assert.ok(c.p256PublicKey(d).equals(q));
  for (const t of v.rfc6979.cases) {
    const want = hex(t.r, t.s);
    assert.ok(c.p256Verify(q, Buffer.from(t.message), want));
    if (c.p256DeterministicNonces()) assert.ok(c.p256Sign(d, Buffer.from(t.message)).equals(want), t.message);
  }
  for (const t of v.keypair) assert.ok(c.p256PublicKey(hex(t.d)).equals(point(t.qx, t.qy)));
  for (const t of v.sigver) assert.strictEqual(c.p256Verify(point(t.qx, t.qy), hex(t.message), hex(t.r, t.s)), t.valid, t.note);
  for (const t of v.siggen) assert.ok(c.p256Verify(point(t.qx, t.qy), hex(t.message), hex(t.r, t.s)));
  assert.strictEqual(v.sigver.length, 15);
});

ok('PKCS#8 import is strict', () => {
  const k = c.p256PrivateKeyFromPem(PEM);
  assert.strictEqual(k.secretKey.toString('hex'), PEM_SK);
  assert.ok(c.p256PublicKey(k.secretKey).equals(k.publicKey));
  const der = Buffer.from(PEM.split('\n').slice(1, 4).join(''), 'base64');
  assert.ok(c.p256PrivateKeyFromPkcs8(der).secretKey.equals(k.secretKey));
  assert.throws(() => c.p256PrivateKeyFromPkcs8(Buffer.concat([der, Buffer.from([0])])), /PrivateKeyInfo/);
  assert.throws(() => c.p256PrivateKeyFromPkcs8(der.subarray(0, 100)), /p256:/);
  assert.throws(() => c.p256PrivateKeyFromPem(PEM.replace('PRIVATE KEY', 'ENCRYPTED PRIVATE KEY')), /encrypted/);
  assert.throws(() => c.p256PrivateKeyFromPem(`junk\n${PEM}`), /PRIVATE KEY block/);
  const ed = crypto.generateKeyPairSync('ed25519').privateKey.export({ format: 'der', type: 'pkcs8' });
  assert.throws(() => c.p256PrivateKeyFromPkcs8(ed), /id-ecPublicKey/);
  const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey.export({ format: 'der', type: 'pkcs8' });
  assert.throws(() => c.p256PrivateKeyFromPkcs8(p384), /P-256/);
});

console.log(`\ncipherbird p256: OK (${pass} passed)`);
