'use strict';
// Extension points: custom ProtectionLayer / CascadeLayer / KeySource / SignatureScheme.
const assert = require('assert');
const c = require('..');
c.init();

const { ProtectionLayer, CascadeLayer, KeySource, SignatureScheme, SignatureAlgorithm } = c;
const secret = Buffer.from('the treaty text nobody may read');
const key = c.randomBytes(32);
let passed = 0;
function t(name, fn) { fn(); passed++; console.log('  ok  ' + name); }

class MyLayer extends ProtectionLayer {
  get id() { return 200; } get wireName() { return 'my-xchacha'; }
  seal(a, k, aad, p) { return a.xchacha20Encrypt(p, k, aad); }
  open(a, k, aad, ct) { return a.xchacha20Decrypt(ct, k, aad); }
}
class BeltAndBraces extends CascadeLayer {
  constructor() { super({ id: 201, wireName: 'belt-and-braces', layers: [ProtectionLayer.xchacha20Poly1305, ProtectionLayer.aes256Gcm, new MyLayer()] }); }
}
class Impostor extends ProtectionLayer {
  get id() { return 3; } get wireName() { return 'committing'; }
  seal(a, k, aad, p) { return p; } open(a, k, aad, ct) { return ct; }
}
class TokenSource extends KeySource {
  constructor(token) { super(); this.token = token; }
  get id() { return 210; } get label() { return 'token'; }
  deriveRoot() { return this.token; }
}
class WeakSource extends KeySource {
  get id() { return 211; } get label() { return 'weak'; }
  deriveRoot() { return Buffer.alloc(16); }
}
class PrefixedEd25519 extends SignatureScheme {
  constructor({ sk = null, pk = null } = {}) { super(); this.sk = sk; this.pk = pk; }
  get id() { return 220; } get label() { return 'prefixed-ed25519'; }
  _tag(m) { return Buffer.concat([Buffer.from('custom:'), m]); }
  sign(a, m) { return a.ed25519Sign(this._tag(m), this.sk); }
  verify(a, m, sig) { return a.ed25519Verify(this._tag(m), sig, this.pk); }
}
class FakeEd25519 extends SignatureScheme {
  get id() { return 1; } get label() { return 'fake'; }
  sign() { return Buffer.alloc(64); } verify() { return true; }
}

t('built-in ids are pinned', () => {
  assert.deepStrictEqual([ProtectionLayer.xchacha20Poly1305, ProtectionLayer.aes256Gcm, ProtectionLayer.committing, ProtectionLayer.molecular].map((l) => l.id), [1, 2, 3, 4]);
  assert.strictEqual(new c.PassphraseKeySource('x').id, 1);
  assert.strictEqual(new c.Ed25519Signature().id, 1);
  assert.strictEqual(new c.HybridSignature().id, 2);
});

t('custom layer round-trips via the registry', () => {
  ProtectionLayer.register(new MyLayer());
  const env = c.recipe().withKey(key).withLayers([new MyLayer()]).seal(secret);
  assert.ok(c.recipe().withKey(key).open(env).equals(secret));
});

t('cascade subclass mixes three ciphers as one layer and fails closed', () => {
  ProtectionLayer.register(new BeltAndBraces());
  const r = c.recipe().withKey(key).withLayers([new BeltAndBraces()]);
  const env = r.seal(secret);
  assert.ok(c.recipe().withKey(key).open(env).equals(secret));
  const bad = Buffer.from(env); bad[bad.length - 1] ^= 1;
  assert.throws(() => r.open(bad));
});

t('cascades nest, mixed with built-ins', () => {
  const nested = new CascadeLayer({ id: 202, wireName: 'nested', layers: [new BeltAndBraces(), ProtectionLayer.committing] });
  ProtectionLayer.register(nested);
  const env = c.recipe().withKey(key).withLayers([ProtectionLayer.xchacha20Poly1305, nested]).seal(secret);
  assert.ok(c.recipe().withKey(key).open(env).equals(secret));
});

t('reserved ids are refused for custom parts', () => {
  assert.throws(() => ProtectionLayer.register(new Impostor()), /reserved/);
  assert.throws(() => c.recipe().withKey(key).addLayer(new Impostor()), /reserved/);
  assert.throws(() => c.recipe().withKey(key).signedWith(new FakeEd25519()), /reserved/);
});

t('re-registering an id under another wireName is refused', () => {
  ProtectionLayer.register(new MyLayer()); // idempotent
  assert.throws(() => ProtectionLayer.register(new CascadeLayer({ id: 200, wireName: 'other', layers: [ProtectionLayer.xchacha20Poly1305] })), /already registered/);
});

t('wireName feeds the key derivation', () => {
  const e1 = c.recipe().withKey(key).withLayers([new MyLayer()]).seal(secret);
  const e2 = c.recipe().withKey(key).withLayers([new CascadeLayer({ id: 203, wireName: 'renamed', layers: [ProtectionLayer.xchacha20Poly1305] })]).seal(secret);
  assert.strictEqual(e1.length, e2.length);
  assert.ok(!e1.equals(e2));
});

t('custom key source round-trips and the header pins its id', () => {
  const token = c.randomBytes(32);
  const env = c.recipe('high').withKeySource(new TokenSource(token)).seal(secret);
  assert.ok(c.recipe('high').withKeySource(new TokenSource(token)).open(env).equals(secret));
  assert.throws(() => c.recipe('high').withKeySource(new TokenSource(c.randomBytes(32))).open(env));
  assert.throws(() => c.recipe('high').withKey(key).open(env), /key source id 210/);
});

t('a key source that narrows the root key is refused', () => {
  assert.throws(() => c.recipe().withKeySource(new WeakSource()).seal(secret), /exactly 32/);
});

t('custom signature scheme round-trips; key-only verifier cannot serve it', () => {
  const id = c.ed25519Keygen();
  const env = c.recipe().withKey(key).signedWith(new PrefixedEd25519({ sk: id.secretKey })).seal(secret);
  assert.ok(c.recipe().withKey(key).verifiedWith(new PrefixedEd25519({ pk: id.publicKey })).open(env).equals(secret));
  assert.throws(() => c.recipe().withKey(key).verifiedBy(id.publicKey).open(env), /scheme id 220/);
  assert.throws(() => c.recipe().withKey(key).open(env), /no verifier/);
  assert.throws(() => c.recipe().withKey(key).verifiedWith(new c.Ed25519Signature({ publicKey: id.publicKey })).open(env), /id 1/);
});

t('built-in shorthands still work with a key-only verifier', () => {
  const hid = c.hybridSigKeygen();
  const r = c.recipe().withKey(key).signedBy(hid.secretKey, SignatureAlgorithm.hybrid).verifiedBy(hid.publicKey);
  assert.ok(r.open(r.seal(secret)).equals(secret));
});

t('describe() names custom parts', () => {
  const d = c.recipe().withKeySource(new TokenSource(c.randomBytes(32))).withLayers([new BeltAndBraces()]).describe();
  assert.ok(d.includes('token') && d.includes('belt-and-braces'));
});

console.log(`extensibility: ${passed} passed`);
