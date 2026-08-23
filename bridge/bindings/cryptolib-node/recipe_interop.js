// Cross-language Recipe interop: seal a fixed set of configurations to a
// directory, or open and verify them.
//   node recipe_interop.js seal|open <dir>
const fs = require('fs');
const c = require('./index.js');

// Fixed inputs so every language derives identical keys.
const KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const SK_HEX = 'd463cb8e5a1b8f2e6c4a90f37d215e08b9c6a4713f2085dcae6b19347c50f2a6';
const PASSPHRASE = 'interop passphrase';
const PLAINTEXT = 'cross-language recipe envelope';

c.init();
const key = Buffer.from(KEY_HEX, 'hex');
const sk = Buffer.from(SK_HEX, 'hex');
const kp = c.ed25519KeygenFromSeed(sk);
const pk = kp.publicKey;
const sigSk = kp.secretKey;

const configs = () => [
  ['balanced', c.recipe().withKey(key)],
  ['maximum', c.recipe('maximum').withKey(key)],
  ['signed', c.recipe('high').withKey(key).signedBy(sigSk, c.SignatureAlgorithm.ed25519).verifiedBy(pk)],
  ['passphrase', c.recipe().withPassphrase(PASSPHRASE).argon2Cost({ ops: 1, memoryBytes: 8 * 1024 * 1024 })],
  ['fec', c.recipe().withKey(key).withFec(c.FecScheme.repetition3)],
];

const [mode, dir] = process.argv.slice(2);
let failures = 0;
for (const [name, r] of configs()) {
  const path = `${dir}/${name}.bin`;
  if (mode === 'seal') {
    fs.writeFileSync(path, r.seal(Buffer.from(PLAINTEXT)));
  } else {
    try {
      const got = r.open(fs.readFileSync(path));
      const ok = got.toString() === PLAINTEXT;
      console.log(`${ok ? '  ok  ' : ' FAIL '} node opens ${name}`);
      if (!ok) failures++;
    } catch (e) {
      console.log(` FAIL  node opens ${name}: ${e.message}`);
      failures++;
    }
  }
}
if (mode === 'seal') console.log(`  node sealed ${configs().length} envelopes`);
process.exit(failures === 0 ? 0 : 1);
