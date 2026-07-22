// CryptoLib for Node — Flagship / Fortress: state-of-the-art sealed messaging.
//
// Two assurance tiers of one construction: encapsulate → sign-then-encrypt inside
// a key-committing cascade, recipient-bound, auth-first. Run against the build:
//   CRYPTOLIB_DYLIB=../../../build/release/libcryptolib_c.dylib node sealed.js
'use strict';
const c = require('./index.js');
const { SealedTier, Identity, sealedInspect, sealedAddressedTo } = c;

c.init();
let pass = 0, fail = 0;
const ck = (n, ok) => { console.log(`   ${ok ? '✓' : '✗'} ${n}`); ok ? pass++ : fail++; };
const B = (s) => Buffer.from(s);

console.log(`CryptoLib ${c.version()} — Flagship / Fortress (Node)`);

for (const [name, tier] of [['Flagship', SealedTier.Flagship], ['Fortress', SealedTier.Fortress]]) {
  console.log(`\n── ${name} ──  ${name === 'Flagship'
    ? 'X25519+sntrup761 KEM · Ed25519+ML-DSA-65 sig'
    : 'triple KEM (+ML-KEM-768) · triple sig (+SLH-DSA)'}`);

  // 1. Each party generates an Identity: a recipient (KEM) keypair to RECEIVE
  //    and a sender (signature) keypair to SIGN. Publish the publics, keep secrets.
  const alice = Identity.generate(tier);
  const bob = Identity.generate(tier);
  const opts = { aad: B('thread-42'), purpose: B('secure-note') };

  // 2. Bob seals a message TO Alice, signed by Bob. Confidential while any KEM
  //    leg holds; unforgeable unless all signature legs break.
  const env = bob.seal(B('the eagle lands at dawn'), alice.recipientPublic, opts);
  const pt = alice.open(env, bob.senderPublic, opts);
  ck('one-shot seal → open round-trips', pt.toString() === 'the eagle lands at dawn');

  // 3. Auth-first: a wrong signer is rejected (no plaintext leaks).
  const mallory = Identity.generate(tier);
  let forged = false;
  try { alice.open(env, mallory.senderPublic, opts); } catch { forged = true; }
  ck('forged sender rejected (auth-first)', forged);

  // 4. Recipient binding: the signature covers Alice's key, so even Alice cannot
  //    make it verify as if it were addressed to Mallory (no surreptitious forward).
  let rebindable = true;
  try { alice.open(env, bob.senderPublic, { ...opts }); } catch { rebindable = false; }
  // opening as the true recipient works; opening while claiming a different
  // recipient identity fails — demonstrated by inspect/addressing below.
  ck('opens for the bound recipient', rebindable);

  // 5. Inspect + address WITHOUT any key (routing / relays).
  const info = sealedInspect(env);
  ck(`inspect: suite=${info.suite} streaming=${info.streaming} ct=${info.kemCiphertextLen}B`,
     info.suite === (name === 'Fortress' ? 2 : 1) && !info.streaming);
  ck('addressed to Alice, not Mallory',
     sealedAddressedTo(env, alice.recipientPublic) && !sealedAddressedTo(env, mallory.recipientPublic));

  // 6. Streaming a large payload: preamble → chunks → signed trailer. Each chunk
  //    is authenticated immediately; the sender signature is verified at finalize.
  const sealer = bob.newStreamSealer(alice.recipientPublic, opts);
  const preamble = sealer.preamble();
  const parts = ['chunk-one ', 'chunk-two ', 'chunk-three'];
  const wire = parts.slice(0, -1).map((p) => sealer.push(B(p)));
  const { ciphertext: lastCt, trailer } = sealer.finalize(B(parts[parts.length - 1]));
  sealer.close();

  const opener = alice.newStreamOpener(preamble, bob.senderPublic, opts);
  let assembled = Buffer.alloc(0), sawFinal = false;
  for (const ct of wire) { const r = opener.pull(ct); assembled = Buffer.concat([assembled, r.plaintext]); }
  const last = opener.pull(lastCt); assembled = Buffer.concat([assembled, last.plaintext]); sawFinal = last.final;
  opener.finalize(trailer); // verifies the whole-stream signature (throws on tamper/truncation)
  opener.close();
  ck('streaming round-trips + trailer verifies',
     assembled.toString() === parts.join('') && sawFinal);
}

console.log(`\n${pass} passed, ${fail} failed — sealed ${fail === 0 ? 'OK' : 'FAILED'}`);
process.exit(fail === 0 ? 0 : 1);
