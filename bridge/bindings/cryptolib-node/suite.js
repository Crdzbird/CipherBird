// CryptoLib for Node — Suite: one-call advanced combinations.
//
// The Suite facade composes hybrid KEM, hybrid signatures, MolecularVault, media
// entropy, keyring, Shamir and Keccak into single calls. Run against the build:
//   CRYPTOLIB_DYLIB=../../../build/release/libcryptolib_c.dylib node suite.js
'use strict';
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const c = require('./index.js');

c.init();
let pass = 0, fail = 0;
const ck = (n, ok) => { console.log(`   ${ok ? '✓' : '✗'} ${n}`); ok ? pass++ : fail++; };
const section = (n) => console.log(`\n${n}`);
const B = (s) => Buffer.from(s);
const aad = B('suite/v1');

console.log(`CryptoLib ${c.version()} — Suite (Node)`);

// 1. Post-quantum message: one call to seal to a recipient's KEM public key.
section('1. Post-quantum message  (suiteSealPq / suiteOpenPq)');
{
  const bob = c.hybridKemKeygen();
  const env = c.suiteSealPq(B('see you at dawn'), bob.publicKey, aad);
  ck('hybrid-KEM sealed message round-trips',
     c.suiteOpenPq(env, bob.secretKey, aad).toString() === 'see you at dawn');
}

// 2. Flagship: post-quantum confidentiality AND authenticity in one call.
section('2. Signed + PQ  (suiteSealSignedPq — the flagship)');
{
  const bob = c.hybridKemKeygen(), signer = c.hybridSigKeygen();
  const pt = B('transfer 100 to acct #42');
  const env = c.suiteSealSignedPq(pt, bob.publicKey, signer.secretKey, aad);
  ck('opens + verifies with the right signer',
     c.suiteOpenSignedPq(env, bob.secretKey, signer.publicKey, aad).equals(pt));
  const impostor = c.hybridSigKeygen();
  let rejected = false;
  try { c.suiteOpenSignedPq(env, bob.secretKey, impostor.publicKey, aad); } catch { rejected = true; }
  ck('rejects a wrong signer (fails closed)', rejected);
}

// 3. File-as-key: the file's deterministic entropy is the key.
section('3. File-as-key  (suiteSealWithFile / suiteOpenWithFile)');
{
  const tmp = path.join(os.tmpdir(), 'cryptolib_node_suite_key.bin');
  fs.writeFileSync(tmp, Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 37 + 11) & 0xff)));
  try {
    const env = c.suiteSealWithFile(B('launch codes'), tmp, aad);
    ck('same file re-derives the key and opens',
       c.suiteOpenWithFile(env, tmp, aad).toString() === 'launch codes');
  } finally { fs.unlinkSync(tmp); }
}

// 4. Keyring-guarded: master never at rest in plaintext; either slot opens.
section('4. Keyring-guarded  (suiteSeal/Open_with_keyring_*)');
{
  const deviceKey = c.randomBytes(32);
  const kr = c.keyringCreate();
  c.keyringAddDeviceSlot(kr, deviceKey);
  c.keyringAddPassphraseSlot(kr, 'cross-device pass', 0);
  const env = c.suiteSealWithKeyringDevice(B('root secret'), kr, deviceKey, aad);
  ck('sealed via device slot, opened via passphrase slot',
     c.suiteOpenWithKeyringPassphrase(env, kr, 'cross-device pass', aad).toString() === 'root secret');
  c.keyringFree(kr);
}

// 5. Threshold (k-of-n): distribute shares, any k reconstruct.
section('5. Threshold  (suiteSealThreshold / suiteOpenThreshold, 3-of-5)');
{
  const { envelope, shares } = c.suiteSealThreshold(B('board resolution'), 5, 3, aad);
  const quorum = [shares[0], shares[2], shares[4]];
  ck(`any 3 of ${shares.length} shares open the envelope`,
     c.suiteOpenThreshold(envelope, quorum, aad).toString() === 'board resolution');
  let below = false;
  try { c.suiteOpenThreshold(envelope, [shares[0], shares[1]], aad); } catch { below = true; }
  ck('below quorum fails', below);
}

// 6. EVM address in one call.
section('6. EVM address  (suiteEvmAddress)');
{
  const w = c.secp256k1Keygen();
  const addr = c.suiteEvmAddress(w.publicKey);
  console.log(`      address 0x${addr.toString('hex')}`);
  ck('derives a 20-byte address', addr.length === 20);
}

console.log(`\n${pass} passed, ${fail} failed — suite ${fail === 0 ? 'OK' : 'FAILED'}`);
process.exit(fail === 0 ? 0 : 1);
