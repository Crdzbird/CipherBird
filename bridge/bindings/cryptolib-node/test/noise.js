// Incremental BLAKE3 + Noise XX through the C ABI.
//   CRYPTOLIB_DYLIB=<path> node test/noise.js
const c = require('..');
let pass = 0, fail = 0;
const ck = (l, ok) => { console.log(`  ${ok ? '✓' : '✗'} ${l}`); ok ? pass++ : fail++; };
const throws = (f) => { try { f(); return false; } catch { return true; } };
c.init();

// ── Noise XX ─────────────────────────────────────────────────────────────────
const iks = c.x25519Keygen(), rks = c.x25519Keygen();
const ini = c.noise(true, iks.publicKey, iks.secretKey, Buffer.from('pro'));
const res = c.noise(false, rks.publicKey, rks.secretKey, Buffer.from('pro'));
const m0 = ini.writeMessage(Buffer.from('hello'));
ck('handshake payload delivered', res.readMessage(m0).toString() === 'hello');
ini.readMessage(res.writeMessage());
res.readMessage(ini.writeMessage());
ck('handshake finished both sides', ini.handshakeFinished() && res.handshakeFinished());
ck('mutual static authentication',
   ini.remoteStatic().equals(rks.publicKey) && res.remoteStatic().equals(iks.publicKey));
ck('handshake hash agrees (32 B)', ini.handshakeHash().length === 32 && ini.handshakeHash().equals(res.handshakeHash()));
ini.split(); res.split();
ck('second split refused', throws(() => ini.split()));

const ct = ini.encrypt(Buffer.from('first record'), Buffer.from('ad'));
ck('transport round-trip', res.decrypt(ct, Buffer.from('ad')).toString() === 'first record');
ck('reverse direction', ini.decrypt(res.encrypt(Buffer.from('reply'))).toString() === 'reply');
const bad = Buffer.from(ct); bad[0] ^= 1;
ck('tampered record rejected', throws(() => res.decrypt(bad, Buffer.from('ad'))));

// decryptAt: out of order, counter untouched, wrong counter + reserved nonce refused.
// 'first record' already consumed sender counter 0, so recs[i] was sealed at
// counter i + BASE — the caller must supply the counter the SENDER used.
const BASE = 1;
const texts = ['r0', 'record one', 'r2', 'r3'];
const recs = texts.map((t) => ini.encrypt(Buffer.from(t)));
let outOfOrderOk = true;
for (let i = recs.length - 1; i >= 0; i--) outOfOrderOk &&= res.decryptAt(BASE + i, recs[i]).toString() === texts[i];
ck('decryptAt opens records out of order', outOfOrderOk);
ck('sequential counter untouched', res.decrypt(recs[0]).toString() === 'r0');
ck('wrong counter rejected', throws(() => res.decryptAt(0, recs[0])));
ck('reserved nonce rejected', throws(() => res.decryptAt(2n ** 64n - 1n, recs[0])));
ck('encrypt before split fails', throws(() => c.noise(true, iks.publicKey, iks.secretKey).encrypt(Buffer.from('x'))));
ini.close(); res.close(); res.close(); // idempotent

// ── Incremental BLAKE3 ───────────────────────────────────────────────────────
const msg = Buffer.from('incremental hashing across several chunks of input');
const want = c.blake3(msg);
const h = c.blake3Hasher();
h.update(msg.subarray(0, 7)); h.update(msg.subarray(7, 20)); h.update(msg.subarray(20));
ck('incremental == one-shot blake3', h.finalize().equals(want));
ck('update after finalize fails', throws(() => h.update(Buffer.from('late'))));
const kh = c.blake3Hasher(Buffer.alloc(32)); kh.update(msg);
ck('keyed digest differs', !kh.finalize().equals(want));
ck('31-byte key refused', throws(() => c.blake3Hasher(Buffer.alloc(31))));
const xh = c.blake3Hasher(); xh.update(msg);
const xof = xh.finalize(64);
ck('XOF prefix equals 32-byte digest', xof.length === 64 && xof.subarray(0, 32).equals(want));
h.close(); kh.close(); xh.close();

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
