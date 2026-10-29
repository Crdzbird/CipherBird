/*
 * The worker-thread runner: heavy calls resolve off the main thread with
 * the same results as the synchronous API, errors come back as errors, and
 * the worker never keeps the process alive.
 *
 * CIPHERBIRD_LIBRARY=<path> node test/async.js
 */
'use strict';
const assert = require('node:assert');
const c = require('..');

const B = (s) => Buffer.from(s);
let pass = 0;
const ok = async (label, f) => { await f(); pass++; console.log(`  ok  ${label}`); };

(async () => {
  await ok('ML-DSA and SLH-DSA sign on the worker, verify on the main thread', async () => {
    const d = await c.async.mlDsaKeygen();
    assert.ok(Buffer.isBuffer(d.publicKey));
    const sig = await c.mlDsaSignAsync(B('m'), d.secretKey);
    assert.ok(c.mlDsaVerify(B('m'), sig, d.publicKey));
    const s = await c.slhDsaKeygenAsync(0, 0);
    assert.ok(c.slhDsaVerify(B('m'), await c.slhDsaSignAsync(B('m'), s.secretKey, 0, 0), s.publicKey, 0, 0));
    const h = c.hybridSigKeygen();
    assert.ok(c.hybridSigVerify(B('m'), await c.hybridSigSignAsync(B('m'), h.secretKey), h.publicKey));
  });

  await ok('Suite v2 and the media methods on bytes round trip through the worker', async () => {
    const bob = c.xwingKeygen(), alice = c.hybridSigKeygen();
    const env = await c.suite2SealAsync(B('async v2'), bob.publicKey, alice.secretKey, B('ctx'));
    assert.strictEqual((await c.suite2OpenAsync(env, bob.secretKey, bob.publicKey, alice.publicKey, B('ctx'))).toString(), 'async v2');
    const head = Buffer.from('P6\n64 64\n255\n');
    const body = Buffer.alloc(64 * 64 * 3);
    for (let i = 0; i < body.length; i++) body[i] = (i * 7 + ((i * i) % 13)) & 0xff;
    const cover = Buffer.concat([head, body]);
    const hidden = await c.stegoEmbedBytesAsync(cover, 'ppmImage', B('hidden'));
    assert.strictEqual((await c.stegoExtractBytesAsync(hidden, 'ppmImage')).toString(), 'hidden');
    const key = c.randomBytes(32);
    const sealed = await c.stegoEmbedEncryptedBytesAsync(cover, 'ppmImage', B('sealed'), key);
    assert.strictEqual((await c.stegoExtractDecryptBytesAsync(sealed, 'ppmImage', key)).toString(), 'sealed');
    assert.strictEqual((await c.keyFromBytesAsync(cover)).length, 32);
  });

  await ok('Argon2id and the easy-mode async helpers', async () => {
    const salt = c.randomBytes(16);
    const sync = c.SymmetricKey.fromPassphrase('pw', { salt, ops: 1, memoryBytes: 8 << 20 });
    const key = await c.easy.symmetricKeyFromPassphraseAsync('pw', { salt, ops: 1, memoryBytes: 8 << 20 });
    assert.ok(key.bytes.equals(sync.bytes));
    const phc = await c.easy.hashPasswordAsync('hunter2');
    assert.ok(phc.startsWith('$argon2id$'));
    assert.strictEqual(await c.easy.verifyPasswordAsync('hunter2', phc), true);
    assert.strictEqual(await c.easy.verifyPasswordAsync('nope', phc), false);
  });

  await ok('dotted paths, errors and unknown methods', async () => {
    assert.strictEqual((await c.async.run('Hpke.keygen')).publicKey.length, 32);
    assert.strictEqual((await c.async.run('easy.sha256Hex', 'abc')), c.easy.sha256Hex('abc'));
    await assert.rejects(c.async.xchacha20Decrypt(B('junk'), c.randomBytes(32)), /too short|cipherbird|auth/i);
    await assert.rejects(c.async.run('noSuchMethod'), /no method/);
    const results = await Promise.all([1, 2, 3].map((i) => c.async.sha256(B(`${i}`))));
    assert.ok(results.every((r, i) => r.equals(c.sha256(B(`${i + 1}`)))));
  });

  await ok('close() ends the worker and a later call restarts it', async () => {
    assert.strictEqual(c.async.alive, true);
    await c.async.close();
    assert.strictEqual(c.async.alive, false);
    assert.strictEqual((await c.async.randomBytes(4)).length, 4);
    await c.async.close();
  });

  console.log(`\ncipherbird async: OK (${pass} passed)`);
})().catch((e) => { console.error('FAILED:', e); process.exit(1); });
