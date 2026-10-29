/*
 * Easy mode: SymmetricKey, SigningKey, VerifyKey, KemKeyPair and the
 * cipherbird.easy helpers, with the byte layouts the Dart packages use.
 *
 * CIPHERBIRD_LIBRARY=<path> node test/easy.js
 */
'use strict';
const assert = require('node:assert');
const c = require('..');

let pass = 0;
const ok = (label, f) => { f(); pass++; console.log(`  ok  ${label}`); };
const B = (s) => Buffer.from(s);

ok('SymmetricKey: generate, encrypt, text, derive, encodings, destroy', () => {
  const key = c.SymmetricKey.generate();
  const box = key.encrypt(B('meet at dawn'), { aad: B('h') });
  assert.strictEqual(key.decrypt(box, { aad: B('h') }).toString(), 'meet at dawn');
  assert.throws(() => key.decrypt(box));
  const text = key.encryptText('meet at dawn', { aad: 'h' });
  assert.strictEqual(key.decryptText(text, { aad: 'h' }), 'meet at dawn');
  assert.ok(c.SymmetricKey.fromHex(key.hex).bytes.equals(key.bytes));
  assert.ok(c.SymmetricKey.fromBase64(key.base64).bytes.equals(key.bytes));
  assert.ok(!key.derive('a').bytes.equals(key.derive('b').bytes));
  assert.ok(key.derive('a').bytes.equals(key.derive('a').bytes));
  const env = c.recipe().withKeySource(key.asKeySource).seal(B('r'));
  assert.strictEqual(c.recipe().withKey(key.bytes).open(env).toString(), 'r');
  assert.throws(() => c.SymmetricKey.fromBytes(Buffer.alloc(5)), RangeError);
  key.destroy();
  assert.ok(key.isDestroyed);
  assert.throws(() => key.encrypt(B('x')), /wiped/);
});

ok('SymmetricKey.fromPassphrase is deterministic per salt', () => {
  const salt = c.randomBytes(16);
  const a = c.SymmetricKey.fromPassphrase('correct horse battery staple', { salt, ops: 1, memoryBytes: 8 << 20 });
  const b = c.SymmetricKey.fromPassphrase(B('correct horse battery staple'), { salt, ops: 1, memoryBytes: 8 << 20 });
  assert.ok(a.bytes.equals(b.bytes));
  assert.ok(!a.bytes.equals(c.SymmetricKey.fromPassphrase('other', { salt, ops: 1, memoryBytes: 8 << 20 }).bytes));
  assert.throws(() => c.SymmetricKey.fromPassphrase('x', { salt: Buffer.alloc(8) }), RangeError);
});

ok('SigningKey and VerifyKey for Ed25519 and the hybrid', () => {
  for (const algorithm of ['ed25519', 'hybrid']) {
    const key = c.SigningKey.generate({ algorithm });
    const sig = key.signText('release 1.3.0');
    assert.ok(key.verifyKey.verifyText('release 1.3.0', sig));
    assert.ok(!key.verifyKey.verifyText('release 1.3.1', sig));
    const again = c.SigningKey.fromBytes({ secretKey: key.secretKey, publicKey: key.publicKey, algorithm });
    assert.ok(again.verify(B('m'), key.sign(B('m'))));
    assert.ok(c.VerifyKey.fromHex(key.publicKey.toString('hex'), { algorithm }).verify(B('m'), key.sign(B('m'))));
    const env = c.recipe().withKey(c.randomBytes(32)).signedWith(key.scheme).seal(B('signed'));
    assert.strictEqual(env[6], key.algorithm);
  }
  assert.throws(() => c.SigningKey.generate({ algorithm: 'rsa' }), TypeError);
});

ok('KemKeyPair: encapsulate, encryptFor and the text forms', () => {
  const me = c.KemKeyPair.generate();
  const { ciphertext, key } = c.KemKeyPair.encapsulate(me.publicKey);
  assert.ok(me.decapsulate(ciphertext).bytes.equals(key.bytes));
  const blob = c.KemKeyPair.encryptFor(me.publicKey, B('hello'), { aad: B('a') });
  assert.strictEqual(blob.readUInt32BE(0), ciphertext.length);
  assert.strictEqual(me.decrypt(blob, { aad: B('a') }).toString(), 'hello');
  assert.throws(() => me.decrypt(blob));
  assert.throws(() => me.decrypt(Buffer.alloc(2)), RangeError);
  const text = c.KemKeyPair.encryptTextFor(me.publicKey, 'hi', { aad: 'x' });
  assert.strictEqual(me.decryptText(text, { aad: 'x' }), 'hi');
  const other = c.KemKeyPair.fromBytes({ publicKey: me.publicKey, secretKey: me.secretKey });
  assert.strictEqual(other.decryptText(text, { aad: 'x' }), 'hi');
});

ok('easy helpers: passwords, tokens, hex and hashes', () => {
  const phc = c.easy.hashPassword('hunter2', { profile: 'balanced' });
  assert.ok(phc.startsWith('$argon2id$'));
  assert.ok(c.easy.verifyPassword('hunter2', phc));
  assert.ok(!c.easy.verifyPassword('hunter3', phc));
  assert.strictEqual(c.easy.randomHex(8).length, 16);
  assert.match(c.easy.token(), /^[A-Za-z0-9_-]{43}$/);
  assert.strictEqual(c.easy.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.strictEqual(c.easy.symmetricKey().bytes.length, 32);
  assert.strictEqual(c.easy.signingKey().algorithm, c.SignatureAlgorithm.ed25519);
  assert.strictEqual(c.easy.kemKeyPair().publicKey.length, c.hybridKemKeygen().publicKey.length);
  assert.ok(c.easy.identity() instanceof c.Identity);
  assert.ok(c.fromHex('0xdead').equals(B([0xde, 0xad])));
  assert.strictEqual(c.toBase64Url(c.fromBase64Url('aGk')), 'aGk');
  assert.ok(c.constantTimeEquals(B('ab'), B('ab')) && !c.constantTimeEquals(B('ab'), B('ac')));
  assert.throws(() => c.fromHex('zz'), TypeError);
});

console.log(`\ncipherbird easy: OK (${pass} passed)`);
