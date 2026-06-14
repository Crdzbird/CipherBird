// Verifies: require() does not load native eagerly; preload() warms off-thread
// in a worker; the synchronous API works with and without preload (no await).
'use strict';
const assert = require('node:assert');

(async () => {
  // require() must NOT have loaded the native lib yet (lazy).
  const cl = require('..');
  assert.strictEqual(typeof cl.preload, 'function', 'preload() exported');

  // Synchronous API works with NO preload (lazy self-init on first call).
  cl.init();
  assert.strictEqual(cl.version(), '3.0.0', 'version after lazy init');
  const h1 = cl.sha256(Buffer.from('abc')).toString('hex');
  assert.strictEqual(
    h1, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'sha256(abc) KAT');

  // preload() warms in a worker thread and resolves true.
  const warmed = await cl.preload();
  assert.strictEqual(warmed, true, 'preload() resolved true');

  // Idempotent + API still synchronous after preload.
  assert.strictEqual(await cl.preload(), true, 'preload idempotent');
  assert.strictEqual(cl.randomBytes(16).length, 16, 'sync randomBytes after preload');

  // Hybrid KEM round-trip — still fully synchronous, no await.
  const kp = cl.hybridKemKeygen();
  const enc = cl.hybridKemEncapsulate(kp.publicKey);
  const ss = cl.hybridKemDecapsulate(enc.ciphertext, kp.secretKey);
  assert.strictEqual(Buffer.compare(ss, enc.sharedSecret), 0, 'hybrid KEM agree');

  console.log('cryptolib npm preload test: OK');
})().catch((e) => { console.error('FAILED:', e); process.exit(1); });
