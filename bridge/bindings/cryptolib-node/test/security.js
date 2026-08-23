// SecurityProfile presets and the composable Recipe pipeline.
//   CRYPTOLIB_DYLIB=<path> node test/security.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const c = require('..');

let pass = 0, fail = 0;
const ck = (label, ok) => { console.log(`  ${ok ? '✓' : '✗'} ${label}`); ok ? pass++ : fail++; };
const throws = (f) => { try { f(); return false; } catch { return true; } };
const cheap = (r) => r.argon2Cost({ ops: 1, memoryBytes: 8 * 1024 * 1024 });

function noisePpm(w, h, seed) {
  const head = Buffer.from(`P6\n${w} ${h}\n255\n`);
  const body = Buffer.alloc(w * h * 3);
  let s = seed >>> 0 || 1;
  for (let i = 0; i < body.length; i++) {
    s ^= (s << 13) >>> 0; s >>>= 0; s ^= s >>> 17; s ^= (s << 5) >>> 0; s >>>= 0;
    body[i] = s & 0xFF;
  }
  return Buffer.concat([head, body]);
}

c.init();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cl_sec_'));
const secret = Buffer.from('the treaty text nobody may read');

// ── Profiles ─────────────────────────────────────────────────────────────────
const max = c.SecurityProfile.params('maximum');
ck('maximum picks the strongest options',
   max.mlKemLevel === 2 && max.mlDsaLevel === 2 && max.slhDsaHash === 1 && max.kdfPreset === 1);
ck('maximum cascade ends key-committing',
   max.cascade.length === 3 && max.cascade[2] === c.ProtectionLayer.committing);
ck('profiles are ordered',
   c.SecurityProfile.params('balanced').argon2Memory < max.argon2Memory);

// ── Round-trips ──────────────────────────────────────────────────────────────
const key = c.Rng.bytes(32);
const r = c.recipe('high').withKey(key);
ck('raw key round-trip', r.open(r.seal(secret)).equals(secret));

const pr = cheap(c.maximumSecurity().withPassphrase('correct horse battery staple'));
ck('maximum + passphrase round-trip', pr.open(pr.seal(secret)).equals(secret));

const keyFile = path.join(dir, 'key.ppm');
fs.writeFileSync(keyFile, noisePpm(96, 96, 0x5EED));
const sealedByFile = c.recipe().withKeyFile(keyFile).seal(secret);
ck('key file reproducible across recipe objects',
   c.recipe().withKeyFile(keyFile).open(sealedByFile).equals(secret));

// ── Composition ──────────────────────────────────────────────────────────────
const mol = c.recipe().withKey(key).withLayers([c.ProtectionLayer.molecular]);
ck('MolecularVault as one layer', mol.open(mol.seal(secret)).equals(secret));

const one = c.recipe().withKey(key).withLayers([c.ProtectionLayer.xchacha20Poly1305]).seal(secret);
const three = c.recipe().withKey(key)
  .withLayers([c.ProtectionLayer.xchacha20Poly1305, c.ProtectionLayer.aes256Gcm])
  .addLayer(c.ProtectionLayer.committing).seal(secret);
ck('each layer adds overhead', three.length > one.length);

const id = c.ed25519Keygen();
const signed = c.recipe('high').withKey(key).signedBy(id.secretKey).verifiedBy(id.publicKey);
const senv = signed.seal(secret);
ck('signed round-trip', signed.open(senv).equals(secret));

const hid = c.hybridSigKeygen();
const hy = c.recipe().withKey(key)
  .signedBy(hid.secretKey, c.SignatureAlgorithm.hybrid).verifiedBy(hid.publicKey);
ck('hybrid PQ signed round-trip', hy.open(hy.seal(secret)).equals(secret));

const impostor = c.ed25519Keygen();
ck('wrong signer rejected',
   throws(() => c.recipe('high').withKey(key).verifiedBy(impostor.publicKey).open(senv)));
ck('signed envelope refuses to open unverified',
   throws(() => c.recipe('high').withKey(key).open(senv)));

// ── FEC + carrier ────────────────────────────────────────────────────────────
const fr = c.recipe().withKey(key).withFec(c.FecScheme.repetition3);
const fenv = fr.seal(secret);
fenv[Math.floor(fenv.length / 2)] ^= 1;
ck('FEC corrects a flipped bit', fr.open(fenv).equals(secret));

const cover = path.join(dir, 'cover.ppm');
const carrier = path.join(dir, 'carrier.ppm');
fs.writeFileSync(cover, noisePpm(256, 256, 0x0FF1CE));
const cr = cheap(c.maximumSecurity().withPassphrase('a long passphrase here'));
cr.sealIntoCarrier(secret, { coverPath: cover, outputPath: carrier });
ck('pipeline hides itself in a carrier', cr.openFromCarrier(carrier).equals(secret));
ck('carrier is still a valid image', c.StegoAdvanced.inspect(carrier).format === 'ppmImage');

// ── Fails closed ─────────────────────────────────────────────────────────────
const tenv = r.seal(secret); tenv[tenv.length - 1] ^= 1;
ck('flipped ciphertext byte rejected', throws(() => r.open(tenv)));
const henv = r.seal(secret); henv[7] = 1;
ck('tampered header rejected (descriptor is AAD)', throws(() => r.open(henv)));
const senv2 = r.seal(secret); senv2[10] ^= 0xFF;
ck('tampered salt rejected', throws(() => r.open(senv2)));
ck('wrong key rejected', throws(() => c.recipe('high').withKey(c.Rng.bytes(32)).open(r.seal(secret))));
ck('foreign bytes rejected', throws(() => r.open(Buffer.from('not an envelope'))));
ck('short key refused', throws(() => c.recipe().withKey(Buffer.alloc(31))));
ck('empty layer list refused', throws(() => c.recipe().withLayers([])));

fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
