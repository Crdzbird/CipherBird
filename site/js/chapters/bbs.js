import { row, mustRefuse, refuses } from '../kit.js';
import { hex, same, utf8, fromHex } from '../bytes.js';

const ATTRIBUTES = [
  'name: Ada Lovelace',
  'birth year: 1990',
  'country: NL',
  'licence class: B',
  'expiry: 2031-06-30',
];

function issuer(cb, seed) {
  const material = cb.call('sha256', seed);
  return cb.call('bbs_keygen', material, 'cipherbird demo issuer');
}

function nymHolder(cb, memberSecret, signerMsgs, committed) {
  const { public_key: pk, secret_key: sk } = issuer(cb, 'pseudonym issuer');
  const header = utf8.encode('membership card v1');
  const proverNym = cb.call('bbs_hash_to_scalar', memberSecret, 'cipherbird nym seed');
  const blind = cb.Out.buffer();
  const commitment = cb.call('bbs_commit_with_nym', committed, [proverNym], blind);
  const entropy = cb.call('bbs_random_scalar');
  const signature = cb.call('bbs_blind_sign_with_nym', sk, pk, commitment, header, signerMsgs, entropy, 1);
  const nymSecret = cb.call('bbs_finalize_nym_secrets', [proverNym], entropy);
  return { pk, header, proverNym, blind: blind.value, commitment, entropy, signature, nymSecret };
}

export default {
  id: 'bbs',
  title: 'BBS credentials and selective disclosure',
  lead: 'BBS signs a list of attributes at once, and the holder can later prove any subset of them in zero knowledge. Per-verifier pseudonyms and blind issuance build anonymous credentials on top.',
  demos: [
    {
      id: 'keys',
      title: 'Issuer keys from seed material',
      statement: 'KeyGen turns at least 32 bytes of key material and an optional key info into a 32-byte secret and a 96-byte public key. The same inputs always give the same keys.',
      inputs: [
        { name: 'seed', label: 'Key material (hashed to 32 bytes)', kind: 'text', value: 'driving licence authority, 2026' },
        { name: 'info', label: 'Key info', kind: 'text', value: 'issuer key 1' },
      ],
      run(cb, { seed, info }) {
        const material = cb.call('sha256', seed);
        const a = cb.call('bbs_keygen', material, info);
        const b = cb.call('bbs_keygen', material, info);
        const other = cb.call('bbs_keygen', material, `${info}/rotated`);
        const derived = cb.call('bbs_sk_to_pk', a.secret_key);
        const short = cb.call('bbs_keygen', material.subarray(0, 16), info);
        return [
          row.bytes('Secret key', a.secret_key),
          row.bytes('Public key (BLS12-381 G2)', a.public_key),
          row.check('Sizes match the ciphersuite', a.secret_key.length === 32 && a.public_key.length === 96,
            `${a.secret_key.length} and ${a.public_key.length} bytes`),
          row.check('Same material and info, same keys', same(a.public_key, b.public_key), 'deterministic'),
          row.check('SkToPk recovers the public key', same(derived, a.public_key), 'identical'),
          row.check('Another key info gives an unrelated key', !same(other.public_key, a.public_key), 'distinct'),
          row.check('Key material under 32 bytes is refused', short.public_key.length === 0, 'empty key pair'),
        ];
      },
    },
    {
      id: 'credential',
      title: 'Sign five attributes at once',
      statement: 'One 80-byte signature covers every attribute and the header. Change any attribute, or the header, and the signature no longer verifies.',
      inputs: [
        { name: 'country', label: 'Country attribute', kind: 'text', value: 'country: NL' },
        { name: 'header', label: 'Header (public context)', kind: 'text', value: 'EU driving licence, schema 3' },
      ],
      run(cb, { country, header }) {
        const { public_key: pk, secret_key: sk } = issuer(cb, 'licence issuer');
        const msgs = ATTRIBUTES.map((a, i) => (i === 2 ? country : a));
        const signature = cb.call('bbs_sign', sk, pk, header, msgs);
        const forged = msgs.map((m, i) => (i === 1 ? 'birth year: 1980' : m));
        return [
          row.table('Signed attributes', ['Index', 'Attribute'], msgs.map((m, i) => [String(i), m])),
          row.bytes('Signature', signature),
          row.check('Signature is 80 bytes', signature.length === 80, `${signature.length} bytes`),
          row.check('The issuer signature verifies', cb.call('bbs_verify', pk, signature, header, msgs) === 1, 'valid'),
          mustRefuse('An edited birth year is refused', () => cb.call('bbs_verify', pk, signature, header, forged)),
          mustRefuse('Reordered attributes are refused',
            () => cb.call('bbs_verify', pk, signature, header, [msgs[1], msgs[0], ...msgs.slice(2)])),
          mustRefuse('Another header is refused', () => cb.call('bbs_verify', pk, signature, `${header} (copy)`, msgs)),
        ];
      },
    },
    {
      id: 'disclosure',
      title: 'Prove two attributes, hide three',
      statement: 'The holder proves country and licence class from the signed credential; name, birth year and expiry never leave the device. Each proof is fresh, so two presentations of one credential cannot be linked by their bytes.',
      inputs: [
        { name: 'nonce', label: 'Verifier nonce (presentation header)', kind: 'text', value: 'car-rental/session/8812' },
      ],
      run(cb, { nonce }) {
        const { public_key: pk, secret_key: sk } = issuer(cb, 'licence issuer');
        const header = utf8.encode('EU driving licence, schema 3');
        const signature = cb.call('bbs_sign', sk, pk, header, ATTRIBUTES);
        const shown = [2, 3];
        const revealed = shown.map((i) => ATTRIBUTES[i]);
        const proof = cb.call('bbs_proof_gen', pk, signature, header, nonce, ATTRIBUTES, shown);
        const again = cb.call('bbs_proof_gen', pk, signature, header, nonce, ATTRIBUTES, shown);
        const verify = (ph, msgs, idx, h = header, p = proof) => cb.call('bbs_proof_verify', pk, p, h, ph, msgs, idx);
        return [
          row.table('What the verifier receives', ['Index', 'Attribute'], shown.map((i, k) => [String(i), revealed[k]]),
            'indexes 0, 1 and 4 stay hidden'),
          row.bytes('Proof', proof),
          row.check('The proof verifies against the issuer key', verify(nonce, revealed, shown) === 1, 'valid'),
          row.check('Two proofs of one signature differ, and both verify', !same(proof, again)
            && verify(nonce, revealed, shown, header, again) === 1, 'different bytes, both valid'),
          row.check('The proof does not carry the signature', !hex(proof).includes(hex(signature).slice(0, 32)), 'signature hidden'),
          mustRefuse('An edited disclosed attribute is refused', () => verify(nonce, ['country: DE', revealed[1]], shown)),
          mustRefuse('Claiming the attribute sits at another index is refused', () => verify(nonce, revealed, [1, 3])),
          mustRefuse('Replaying the proof under another nonce is refused', () => verify(`${nonce}x`, revealed, shown)),
          mustRefuse('The proof under another header is refused', () => verify(nonce, revealed, shown, 'EU driving licence, schema 4')),
        ];
      },
    },
    {
      id: 'pseudonyms',
      title: 'One pseudonym per verifier',
      statement: 'The holder commits to a secret the issuer never sees, and the signed credential carries it. Each verifier context then sees a stable pseudonym that cannot be linked to the pseudonym another verifier sees.',
      inputs: [
        { name: 'member', label: 'Holder secret', kind: 'text', value: 'member 4471, device key' },
        { name: 'library', label: 'Verifier A context', kind: 'text', value: 'city-library.example' },
        { name: 'gym', label: 'Verifier B context', kind: 'text', value: 'gym.example' },
      ],
      run(cb, { member, library, gym }) {
        const signerMsgs = ['membership: gold', 'valid until: 2027-12'];
        const committed = ['holder email: ada@example.org'];
        const h = nymHolder(cb, member, signerMsgs, committed);
        const nymA = cb.call('bbs_calculate_pseudonym', library, [h.nymSecret]);
        const nymA2 = cb.call('bbs_calculate_pseudonym', library, [h.nymSecret]);
        const nymB = cb.call('bbs_calculate_pseudonym', gym, [h.nymSecret]);
        const ph = utf8.encode('visit 1');
        const out = cb.Out.buffer();
        const proof = cb.call('bbs_proof_gen_with_pseudonym', h.pk, h.signature, h.header, ph, library,
          signerMsgs, committed, h.blind, [h.nymSecret], [0], [], out);
        const out2 = cb.Out.buffer();
        const proof2 = cb.call('bbs_proof_gen_with_pseudonym', h.pk, h.signature, h.header, ph, library,
          signerMsgs, committed, h.blind, [h.nymSecret], [0], [], out2);
        const L = signerMsgs.length;
        const check = (ctx, nym, p = proof) => cb.call('bbs_proof_verify_with_pseudonym', h.pk, p, h.header, ph,
          ctx, nym, L, 1, [signerMsgs[0]], [0]);
        return [
          row.bytes('Pseudonym at verifier A', nymA),
          row.bytes('Pseudonym at verifier B', nymB),
          row.check('Verifier A sees the same pseudonym every time', same(nymA, nymA2) && same(out.value, nymA)
            && same(out2.value, nymA), 'stable'),
          row.check(library === gym ? 'Verifier B shares the context of A' : 'Verifier B sees a different pseudonym',
            library === gym || !same(nymA, nymB), library === gym ? 'same context' : 'unlinkable across contexts'),
          row.check('The nym secret differs from the committed seed', !same(h.nymSecret, h.proverNym),
            'issuer entropy mixed in'),
          row.check('The pseudonym-bound proof verifies at A', check(library, out.value) === 1, 'valid'),
          row.check('Two visits give different proofs, same pseudonym', !same(proof, proof2)
            && check(library, out2.value, proof2) === 1, 'fresh proof'),
          ...(library === gym ? [row.text('Verifier B', 'same context as A, so the same pseudonym')] : [
            mustRefuse('The proof for A is refused at B', () => check(gym, nymB)),
            mustRefuse('The proof with B\'s pseudonym is refused at A', () => check(library, nymB)),
          ]),
        ];
      },
    },
    {
      id: 'pseudonym-committed',
      title: 'Disclose a committed attribute later',
      statement: 'Attributes the holder committed to at issuance can still be disclosed in a proof. The verifier indexes them after the signer attributes, skipping one slot: committed index j is L + 1 + j.',
      inputs: [{ name: 'email', label: 'Committed attribute', kind: 'text', value: 'holder email: ada@example.org' }],
      run(cb, { email }) {
        const signerMsgs = ['membership: gold', 'valid until: 2027-12'];
        const committed = [email, 'holder phone: +31 20 555 0100'];
        const h = nymHolder(cb, 'member 4471, device key', signerMsgs, committed);
        const ctx = utf8.encode('mailing-list.example');
        const ph = utf8.encode('subscribe');
        const out = cb.Out.buffer();
        const proof = cb.call('bbs_proof_gen_with_pseudonym', h.pk, h.signature, h.header, ph, ctx,
          signerMsgs, committed, h.blind, [h.nymSecret], [1], [0], out);
        const L = signerMsgs.length;
        const idx = [1, L + 1];
        const verify = (msgs, indexes) => cb.call('bbs_proof_verify_with_pseudonym', h.pk, proof, h.header, ph,
          ctx, out.value, L, 1, msgs, indexes);
        return [
          row.table('Disclosed', ['Verifier index', 'Attribute'], [[String(idx[0]), signerMsgs[1]], [String(idx[1]), email]],
            'the phone number stays hidden'),
          row.bytes('Commitment the issuer signed', h.commitment),
          row.bytes('Pseudonym', out.value),
          row.check('The proof verifies with the combined indexes', verify([signerMsgs[1], email], idx) === 1, 'valid'),
          mustRefuse('Indexing the committed attribute at L instead of L + 1 is refused',
            () => verify([signerMsgs[1], email], [1, L])),
          mustRefuse('An edited committed attribute is refused',
            () => verify([signerMsgs[1], 'holder email: eve@example.org'], idx)),
        ];
      },
    },
    {
      id: 'blind',
      title: 'Sign what you cannot see',
      statement: 'The holder sends only a commitment to a private attribute, and the issuer signs it next to its own attributes. The holder checks the result with the blinding factor it kept.',
      inputs: [{ name: 'secret', label: 'Private attribute', kind: 'text', value: 'wallet binding key 7f3a' }],
      run(cb, { secret }) {
        const { public_key: pk, secret_key: sk } = issuer(cb, 'blind issuer');
        const header = utf8.encode('employee badge');
        const committed = [secret];
        const blindOut = cb.Out.buffer();
        const commitment = cb.call('bbs_blind_commit', committed, blindOut);
        const blind = blindOut.value;
        const signerMsgs = ['department: research', 'clearance: 2'];
        const signature = cb.call('bbs_blind_sign', sk, pk, commitment, header, signerMsgs);
        const verify = (c, b) => cb.call('bbs_verify_blind_sign', pk, signature, header, signerMsgs, c, b);
        const badBlind = Uint8Array.from(blind);
        badBlind[31] ^= 1;
        const plain = refuses(() => cb.call('bbs_verify', pk, signature, header, [...signerMsgs, secret]));
        return [
          row.bytes('Commitment sent to the issuer', commitment),
          row.bytes('Secret prover blind (kept by the holder)', blind),
          row.check('The commitment does not contain the attribute', !hex(commitment).includes(hex(utf8.encode(secret))),
            'hidden'),
          row.bytes('Blind signature', signature),
          row.check('The holder verifies the blind signature', verify(committed, blind) === 1, 'valid'),
          mustRefuse('Another private attribute is refused', () => verify([`${secret}!`], blind)),
          mustRefuse('A wrong blinding factor is refused', () => verify(committed, badBlind)),
          row.check('It is not a plain signature over the same attributes', plain.refused, 'blind suite'),
        ];
      },
    },
    {
      id: 'scalars',
      title: 'Canonical scalars for nyms',
      statement: 'Pseudonym inputs must be scalars below the group order; a raw 32-byte value is too large more than half the time. hash_to_scalar maps any secret to a stable one, random_scalar draws a fresh one.',
      inputs: [{ name: 'secret', label: 'Holder secret', kind: 'text', value: 'member-secret-42' }],
      run(cb, { secret }) {
        const msg = fromHex('9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02');
        const kat = cb.call('bbs_hash_to_scalar', msg, 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_H2S_');
        const a = cb.call('bbs_hash_to_scalar', secret, 'nym-seed');
        const b = cb.call('bbs_hash_to_scalar', secret, 'nym-seed');
        const other = cb.call('bbs_hash_to_scalar', secret, 'nym-seed/2');
        const r1 = cb.call('bbs_random_scalar');
        const r2 = cb.call('bbs_random_scalar');
        const order = BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');
        const below = [a, r1, r2].every((s) => BigInt(`0x${hex(s)}`) < order);
        return [
          row.bytes('hash_to_scalar(secret, "nym-seed")', a),
          row.bytes('random_scalar', r1),
          row.check('Matches the BBS draft test vector', hex(kat) === '0f90cbee27beb214e6545becb8404640d3612da5d6758dffeccd77ed7169807c',
            'known answer'),
          row.check('Same secret and tag, same scalar', same(a, b), 'deterministic'),
          row.check('Another tag, another scalar', !same(a, other), 'domain separated'),
          row.check('Two random scalars differ', !same(r1, r2), 'distinct'),
          row.check('Every scalar is below the group order r', below, 'canonical'),
        ];
      },
    },
  ],
};
