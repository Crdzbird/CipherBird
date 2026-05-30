// Smoke test: load the WASM module (no native lib) and round-trip.
const load = require('..');

(async () => {
  let pass = 0, fail = 0;
  const ck = (label, ok) => {
    console.log(`  ${ok ? '✓' : '✗'} ${label}`);
    if (ok) pass++; else fail++;
  };
  const hex = (u8) => Buffer.from(u8).toString('hex');
  const eq  = (a, b) => Buffer.from(a).equals(Buffer.from(b));

  const cryptolib = await load();
  ck('version == 3.0.0', cryptolib.version() === '3.0.0');

  const enc = new TextEncoder();
  ck('SHA-256("abc") KAT',
     hex(cryptolib.sha256(enc.encode('abc'))) ===
     'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

  // X25519 ECDH: Alice and Bob derive the same shared secret.
  const a = cryptolib.x25519Keygen();
  const b = cryptolib.x25519Keygen();
  const s_ab = cryptolib.x25519SharedSecret(a.secretKey, b.publicKey);
  const s_ba = cryptolib.x25519SharedSecret(b.secretKey, a.publicKey);
  ck('X25519 ECDH agreement (browser-side)', eq(s_ab, s_ba) && s_ab.length === 32);

  console.log(`\ncryptolib WASM smoke: ${fail === 0 ? 'OK' : 'FAILED'} (${pass} passed, ${fail} failed)`);
  process.exit(fail === 0 ? 0 : 1);
})();
