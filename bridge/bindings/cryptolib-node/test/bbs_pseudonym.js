// BBS per-verifier pseudonym / blind-issuance verify — round-trips across the boundary.
//   CRYPTOLIB_DYLIB=<path> node test/bbs_pseudonym.js
const c = require('..');
const { Bbs } = c;

let pass = 0, fail = 0;
const ck = (label, ok) => { console.log(`  ${ok ? '✓' : '✗'} ${label}`); ok ? pass++ : fail++; };
const hx = (s) => Buffer.from(s, 'hex');

c.init();

const sk = hx('60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc');
const pk = hx('a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c');
const header = hx('11223344556677889900aabbccddeeff');
const ph = hx('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501');
const ctx = hx('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a');
const entropy = hx('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5');
const proverNym = hx('1234000000000000000000000000000000000000000000000000000000000000');

const signer = [Buffer.from([0xaa]), Buffer.from([0xbb, 0xbb])];
const committed = [Buffer.from([0xcc, 0xcc, 0xcc]), Buffer.from([0xdd])];
const nyms = [proverNym];

const { commitmentWithProof, secretProverBlind } = Bbs.commitWithNym(committed, nyms);
ck('commitWithNym (blind == 32 B)', commitmentWithProof.length > 0 && secretProverBlind.length === 32);

const sig = Bbs.blindSignWithNym(sk, pk, commitmentWithProof, header, signer, entropy, 1);
ck('blindSignWithNym (80-byte sig)', sig.length === 80);

const nymSecrets = Bbs.finalizeNymSecrets(nyms, entropy);
ck('finalizeNymSecrets (32 B)', nymSecrets.length === 32);
const ns = [nymSecrets];

const { proof, pseudonym } = Bbs.proofGenWithPseudonym(pk, sig, header, ph, ctx, signer, committed, secretProverBlind, ns, [0, 1], [0, 1]);
ck('proofGenWithPseudonym (pseudonym == 48 B)', proof.length > 0 && pseudonym.length === 48);
ck('pseudonym matches calculatePseudonym', pseudonym.equals(Bbs.calculatePseudonym(ctx, ns)));

const dm = [Buffer.from([0xaa]), Buffer.from([0xbb, 0xbb]), Buffer.from([0xcc, 0xcc, 0xcc]), Buffer.from([0xdd])];
ck('proofVerifyWithPseudonym = VALID', Bbs.proofVerifyWithPseudonym(pk, proof, header, ph, ctx, pseudonym, 2, 1, dm, [0, 1, 3, 4]));

const badctx = hx('aab4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a');
ck('wrong-context proof rejected', !Bbs.proofVerifyWithPseudonym(pk, proof, header, ph, badctx, pseudonym, 2, 1, dm, [0, 1, 3, 4]));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
