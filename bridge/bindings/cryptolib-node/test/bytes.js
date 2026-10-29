/*
 * The media methods on bytes: steganography, the composed seals and media
 * entropy over in-memory carriers, plus KeyBytesSource in a recipe. Mirrors
 * the Dart media_bytes_test.
 *
 * CIPHERBIRD_LIBRARY=<path> node test/bytes.js
 */
'use strict';
const assert = require('node:assert');
const c = require('..');

let pass = 0;
const ok = (label, f) => { f(); pass++; console.log(`  ok  ${label}`); };
const B = (s) => Buffer.from(s);

/** A synthetic photograph: a PPM whose pixels carry structured noise. */
function photoPpm(size, seed) {
  const head = Buffer.from(`P6\n${size} ${size}\n255\n`);
  const body = Buffer.alloc(size * size * 3);
  let s = (seed | 1) >>> 0;
  for (let i = 0; i < body.length; i++) {
    s ^= (s << 13) >>> 0; s ^= s >>> 17; s ^= (s << 5) >>> 0;
    body[i] = Math.max(0, Math.min(255, 128 + (i % 64) + (s % 24) - 12));
  }
  return Buffer.concat([head, body]);
}

const cover = photoPpm(128, 3);
const keyPhoto = photoPpm(64, 99);
const secret = B('the eagle lands at dawn');
const ppm = c.MediaFormat.ppmImage;

ok('MediaFormat names, values and extensions line up', () => {
  assert.strictEqual(ppm, 0);
  assert.strictEqual(c.MediaFormat[ppm], 'ppmImage');
  assert.strictEqual(c.MediaFormat.extensionOf(ppm), 'ppm');
  assert.strictEqual(c.MediaFormat.extensionOf('pngImage'), 'png');
  assert.strictEqual(c.MediaFormat.extensionOf('jpg'), 'jpg');
  assert.throws(() => c.MediaFormat.extensionOf({}), TypeError);
});

ok('plain, keyed and encrypted stego round trips on bytes', () => {
  assert.ok(c.stegoCapacityOf(cover, ppm) > secret.length);
  const hidden = c.stegoEmbedBytes(cover, ppm, secret);
  assert.strictEqual(hidden.length, cover.length);
  assert.ok(c.stegoExtractBytes(hidden, ppm).equals(secret));
  const key = c.randomBytes(32);
  const keyed = c.stegoEmbedKeyedBytes(cover, 'ppmImage', secret, key);
  assert.ok(c.stegoExtractKeyedBytes(keyed, 'ppm', key).equals(secret));
  assert.throws(() => c.stegoExtractKeyedBytes(keyed, ppm, c.randomBytes(32)));
  const sealed = c.stegoEmbedEncryptedBytes(cover, ppm, secret, key);
  assert.ok(c.stegoExtractDecryptBytes(sealed, ppm, key).equals(secret));
  assert.strictEqual(c.stegoDetectHiddenBytes(hidden, ppm).cipherbirdPayload, true);
  assert.strictEqual(c.stegoDetectHiddenBytes(sealed, ppm).cipherbirdPayload, false);
});

ok('inspect and digest see the decoded content', () => {
  const r = c.stegoInspectBytes(cover, ppm);
  assert.strictEqual(r.parses, true);
  assert.strictEqual(r.format, 'ppmImage');
  assert.strictEqual(r.width, 128);
  const d = c.stegoContentDigestOf(cover, ppm);
  assert.strictEqual(d.length, 32);
  assert.ok(d.equals(c.stegoContentDigestOf(cover, ppm)));
});

ok('physical, hpke and image-factor seals on bytes', () => {
  const aad = B('ctx');
  const physical = c.physicalSealBytes({ keyMedia: keyPhoto, keyMediaFormat: ppm, plaintext: secret, cover, coverFormat: ppm, aad });
  assert.ok(c.physicalOpenBytes({ keyMedia: keyPhoto, keyMediaFormat: ppm, stego: physical, stegoFormat: ppm, aad }).equals(secret));
  const bob = c.Hpke.keygen();
  const sealed = c.hpkeStegoSealBytes({ recipientPublic: bob.publicKey, plaintext: secret, cover, coverFormat: ppm });
  assert.ok(c.hpkeStegoOpenBytes({ recipientSecret: bob.secretKey, enc: sealed.enc, stego: sealed.carrier, stegoFormat: ppm }).equals(secret));
  const seed = c.randomBytes(32);
  const factor = c.imageFactorSealBytes({ oprfSecretSeed: seed, referenceImage: keyPhoto, referenceFormat: ppm, plaintext: secret, cover, coverFormat: ppm });
  assert.ok(c.imageFactorOpenBytes({ oprfSecretSeed: seed, referenceImage: keyPhoto, referenceFormat: ppm, stego: factor, stegoFormat: ppm }).equals(secret));
});

ok('media entropy on bytes: policy, keys, seals and the recipe source', () => {
  const h = c.assessHealthOf(cover);
  assert.ok(h.minEntropyPerByte > 1.0);
  assert.throws(() => c.entropyFromBytes(Buffer.alloc(4096)), /policy floor|repetition/);
  const handle = c.entropyFromBytes(cover, { deterministic: true });
  assert.ok(c.entropyInfo(handle).entropyBits > 0);
  c.entropyFree(handle);
  assert.strictEqual(c.keyFromBytes(cover).length, 32);
  const packet = c.sealWithBytes(cover, 'hello', 'aad');
  assert.strictEqual(c.openWithBytes(cover, packet, 'aad').toString(), 'hello');
  assert.throws(() => c.openWithBytes(keyPhoto, packet, 'aad'));
  const env = c.recipe().withKeySource(new c.KeyBytesSource(cover)).seal(secret);
  assert.ok(c.recipe().withKeySource(new c.KeyBytesSource(cover)).open(env).equals(secret));
  assert.throws(() => c.recipe().withKeySource(new c.KeyBytesSource(keyPhoto)).open(env));
  assert.strictEqual(env[5], 3);
});

ok('the namespaces reach the same byte methods', () => {
  assert.ok(c.stego.extractBytes(c.stego.embedBytes(cover, ppm, secret), ppm).equals(secret));
  assert.strictEqual(c.entropy.keyFromBytes(cover).length, 32);
  assert.ok(c.entropy.assessHealthOf(cover).healthy);
});

ok('scratch files are removed afterwards', () => {
  const s = new c.MediaScratch();
  const fs = require('node:fs');
  const p = s.put('bin', B('x'));
  assert.ok(fs.existsSync(p));
  assert.strictEqual(s.take(p).toString(), 'x');
  assert.ok(!fs.existsSync(p));
  s.dispose();
  s.dispose();
});

console.log(`\ncipherbird bytes: OK (${pass} passed)`);
