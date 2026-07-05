// CryptoLib for Node — Recipes: composition in practice.
//
// The primitives are LEGO bricks; these recipes snap them together into
// real-world flows. Run against the local build:
//   CRYPTOLIB_DYLIB=../../../build/release/libcryptolib_c.dylib node recipes.js
'use strict';
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const c = require('./index.js');

c.init();
let pass = 0, fail = 0;
const ck = (name, ok) => { console.log(`   ${ok ? '✓' : '✗'} ${name}`); ok ? pass++ : fail++; };
const section = (n) => console.log(`\n${n}`);
const B = (s) => Buffer.from(s);
const aad = B('recipe/v1');

console.log(`CryptoLib ${c.version()} — Recipes (Node)`);

// 1. File-as-key vault: derive a deterministic master from a file → MolecularVault.
section('1. File-as-key vault  (media entropy → MolecularVault)');
{
  const tmp = path.join(os.tmpdir(), 'cryptolib_node_recipe_key.bin');
  fs.writeFileSync(tmp, Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 37 + 11) & 0xff)));
  const e1 = c.entropyFromFileDeterministic(tmp);
  const master = c.entropyDeriveAll(e1).vaultMasterKey;
  c.entropyFree(e1);
  const env = c.molecularSealWithKey(B('launch codes'), master, aad);
  // other side: same file → same key → open
  const e2 = c.entropyFromFileDeterministic(tmp);
  const master2 = c.entropyDeriveAll(e2).vaultMasterKey;
  c.entropyFree(e2);
  ck('same file re-derives the key and opens the vault',
     c.molecularOpenWithKey(env, master2, aad).toString() === 'launch codes');
  fs.unlinkSync(tmp);
}

// 2. Post-quantum message: hybrid KEM shared secret → MolecularVault.
section('2. Post-quantum message  (hybrid KEM → MolecularVault)');
{
  const bob = c.hybridKemKeygen();
  const { ciphertext, sharedSecret } = c.hybridKemEncapsulate(bob.publicKey); // sender
  const env = c.molecularSealWithKey(B('see you at dawn'), sharedSecret, aad);
  const ss = c.hybridKemDecapsulate(ciphertext, bob.secretKey);               // recipient
  ck('hybrid-KEM secret opens the PQ-sealed message',
     c.molecularOpenWithKey(env, ss, aad).toString() === 'see you at dawn');
}

// 3. Sign-then-seal: hybrid signature carried inside a MolecularVault.
section('3. Sign-then-seal  (hybrid signature inside MolecularVault)');
{
  const signer = c.hybridSigKeygen();
  const msg = B('transfer 100 to acct #42');
  const sig = c.hybridSigSign(msg, signer.secretKey);
  const bundle = Buffer.concat([msg, sig]);
  const env = c.molecularSeal(bundle, 'outer passphrase', aad, 2, 1 << 20);
  const opened = c.molecularOpen(env, 'outer passphrase', aad);
  const gotMsg = opened.subarray(0, msg.length), gotSig = opened.subarray(msg.length);
  ck('opened → both Ed25519 and ML-DSA signatures verify',
     c.hybridSigVerify(gotMsg, gotSig, signer.publicKey) && gotMsg.equals(msg));
}

// 4. EVM wallet: secp256k1 → Keccak address → sign tx digest → ecrecover.
section('4. EVM wallet  (secp256k1 → Keccak address → sign → ecrecover)');
{
  const w = c.secp256k1Keygen();
  const addr = c.keccak256(w.publicKey.subarray(1)).subarray(12, 32); // last 20 bytes
  console.log(`      address 0x${addr.toString('hex')}`);
  const digest = c.keccak256(B('transfer 1 ETH → 0xBEEF'));
  const sig = c.secp256k1Sign(digest, w.secretKey);                   // 65B r‖s‖v
  const recovered = c.secp256k1Recover(digest, sig);
  ck('ecrecover returns the signer public key (65B, v included)',
     sig.length === 65 && recovered.equals(w.publicKey));
}

// 5. Keyring-guarded vault: master wrapped under device + passphrase → MolecularVault.
section('5. Keyring-guarded vault  (Keyring unlock → MolecularVault key)');
{
  const deviceKey = c.randomBytes(32);
  const kr = c.keyringCreate();
  c.keyringAddDeviceSlot(kr, deviceKey);
  c.keyringAddPassphraseSlot(kr, 'cross-device pass', 0);
  const blob = c.keyringSerialise(kr);
  const kr2 = c.keyringDeserialise(blob);
  const master = c.keyringUnlockWithDevice(kr2, deviceKey);
  const env = c.molecularSealWithKey(B('root secret'), master, aad);
  const master2 = c.keyringUnlockWithPassphrase(kr2, 'cross-device pass');
  ck('either keyring factor unlocks the same MolecularVault master',
     c.molecularOpenWithKey(env, master2, aad).toString() === 'root secret' && master.equals(master2));
  c.keyringFree(kr); c.keyringFree(kr2);
}

console.log(`\n${pass} passed, ${fail} failed — recipes ${fail === 0 ? 'OK' : 'FAILED'}`);
process.exit(fail === 0 ? 0 : 1);
