// Smoke test: require the package (no path) and round-trip across the boundary.
const c = require('..');

let pass = 0, fail = 0;
const ck = (label, ok) => { console.log(`  ${ok ? '✓' : '✗'} ${label}`); ok ? pass++ : fail++; };

c.init();
ck('version == 3.0.0', c.version() === '3.0.0');
ck('SHA-256("abc") KAT',
   c.sha256(Buffer.from('abc')).toString('hex') ===
   'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

const msg = Buffer.from('secret payload');
const sk = c.symKeygen();
ck('XChaCha20 round-trip', c.xchacha20Decrypt(c.xchacha20Encrypt(msg, sk), sk).equals(msg));

const hk = c.hybridKemKeygen();
const { ciphertext, sharedSecret } = c.hybridKemEncapsulate(hk.publicKey);
ck('Hybrid X25519+ML-KEM-768 round-trip',
   c.hybridKemDecapsulate(ciphertext, hk.secretKey).equals(sharedSecret) && sharedSecret.length === 32);

const factor = c.randomBytes(32);
const kr = c.keyringCreate();
c.keyringAddDeviceSlot(kr, factor);
c.keyringAddPassphraseSlot(kr, 'cross-device pass', 0);
const blob = c.keyringSerialise(kr);
const kr2 = c.keyringDeserialise(blob);
ck('Keyring device==passphrase master',
   c.keyringUnlockWithDevice(kr2, factor).equals(c.keyringUnlockWithPassphrase(kr2, 'cross-device pass')));
c.keyringFree(kr); c.keyringFree(kr2);

console.log(`\ncryptolib npm smoke: ${fail === 0 ? 'OK' : 'FAILED'} (${pass} passed, ${fail} failed)`);
process.exit(fail === 0 ? 0 : 1);
