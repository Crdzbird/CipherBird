import { row, mustRefuse } from '../kit.js';
import { same, hex, fromHex, flipBit } from '../bytes.js';

const rfcVectors = [
  ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
    '8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805',
    '90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae'],
  ['4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
    'f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02',
    'eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031'],
  ['c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
    '9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e',
    '645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f'],
];

const ticket = (beta) => Number(BigInt(`0x${hex(beta.subarray(0, 6))}`));

export default {
  id: 'vrf',
  title: 'Verifiable random functions',
  lead: 'ECVRF (RFC 9381) maps an input to a random-looking 64-byte output that only the key holder can compute and anyone can check. It is how a lottery or a leader election can be fair without a trusted dealer.',
  demos: [
    {
      id: 'vrf-prove',
      title: 'Prove, hash, verify',
      statement: 'The key holder proves an input and gets an 80-byte proof; the output is a hash of that proof. A verifier with the public key alone recovers the same output.',
      inputs: [{ name: 'alpha', label: 'Input', kind: 'text', value: 'round 7 of the draw' }],
      run(cb, { alpha }) {
        const kp = cb.call('ecvrf_keygen');
        const pi = cb.call('ecvrf_prove', kp.secret_key, alpha);
        const beta = cb.call('ecvrf_proof_to_hash', pi);
        const checked = cb.call('ecvrf_verify', kp.public_key, alpha, pi);
        const again = cb.call('ecvrf_prove', kp.secret_key, alpha);
        return [
          row.bytes('Public key', kp.public_key),
          row.bytes('Proof', pi),
          row.bytes('Output', beta),
          row.check('The public key derives from the secret seed', same(cb.call('ecvrf_public_key', kp.secret_key), kp.public_key), 'matches'),
          row.check('Verification returns the same output', same(checked, beta), 'identical'),
          row.check('Same key and input, same proof and output', same(again, pi), 'deterministic'),
          row.check('Another input gives an unrelated output',
            !same(cb.call('ecvrf_proof_to_hash', cb.call('ecvrf_prove', kp.secret_key, `${alpha}.`)), beta), 'distinct'),
        ];
      },
    },
    {
      id: 'vrf-refuse',
      title: 'Proofs that do not transfer',
      statement: 'A proof is bound to one key and one input. Presented for another input, under another key, or with a single bit changed, it is refused.',
      inputs: [{ name: 'alpha', label: 'Input', kind: 'text', value: 'ticket 1234' }],
      run(cb, { alpha }) {
        const kp = cb.call('ecvrf_keygen');
        const other = cb.call('ecvrf_keygen');
        const pi = cb.call('ecvrf_prove', kp.secret_key, alpha);
        return [
          row.bytes('Proof', pi),
          row.check('The proof verifies for its key and input', cb.call('ecvrf_verify', kp.public_key, alpha, pi).length === 64, 'valid'),
          mustRefuse('Refused for another input', () => cb.call('ecvrf_verify', kp.public_key, `${alpha}0`, pi)),
          mustRefuse('Refused under another public key', () => cb.call('ecvrf_verify', other.public_key, alpha, pi)),
          mustRefuse('Refused with one flipped bit', () => cb.call('ecvrf_verify', kp.public_key, alpha, flipBit(pi, 40))),
        ];
      },
    },
    {
      id: 'vrf-lottery',
      title: 'A lottery nobody can rig',
      statement: 'Each player proves the public round seed with their own key, and the lowest output wins. Nobody can choose their output, and everyone can check everyone else\'s.',
      inputs: [
        { name: 'seed', label: 'Round seed', kind: 'text', value: 'draw 2026-11-20' },
        { name: 'players', label: 'Players', kind: 'number', value: 5, min: 2, max: 12 },
      ],
      run(cb, { seed, players }) {
        const n = Math.max(2, Math.min(12, Number(players)));
        const entries = Array.from({ length: n }, (_, k) => {
          const kp = cb.call('ecvrf_keygen');
          const pi = cb.call('ecvrf_prove', kp.secret_key, seed);
          return { name: `player ${k + 1}`, pk: kp.public_key, pi };
        });
        const verified = entries.map((e) => ({ ...e, beta: cb.call('ecvrf_verify', e.pk, seed, e.pi) }));
        verified.sort((x, y) => ticket(x.beta) - ticket(y.beta));
        const winner = verified[0];
        const claimed = cb.call('ecvrf_proof_to_hash', winner.pi);
        return [
          row.table('Entries, lowest ticket first', ['Player', 'Ticket (first 6 bytes of output)', 'Proof'],
            verified.map((e) => [e.name, String(ticket(e.beta)), 'verified'])),
          row.text('Winner', winner.name),
          row.check('Every proof verified before the draw', verified.length === n, `${n} of ${n}`),
          row.check('The winner\'s own output matches what everyone verified', same(claimed, winner.beta), 'identical'),
          mustRefuse('The winning proof cannot be reused for the next round', () => cb.call('ecvrf_verify', winner.pk, `${seed} next`, winner.pi)),
        ];
      },
    },
    {
      id: 'vrf-rfc',
      title: 'RFC 9381 known answers',
      statement: 'ECVRF-EDWARDS25519-SHA512-TAI is deterministic. The engine reproduces the three vectors of RFC 9381 Appendix B.3: public key, proof and output.',
      inputs: [],
      run(cb) {
        const body = rfcVectors.map(([sk, pk, alpha, pi, beta]) => {
          const proof = cb.call('ecvrf_prove', fromHex(sk), fromHex(alpha));
          const ok = hex(cb.call('ecvrf_public_key', fromHex(sk))) === pk
            && hex(proof) === pi
            && hex(cb.call('ecvrf_proof_to_hash', proof)) === beta
            && hex(cb.call('ecvrf_verify', fromHex(pk), fromHex(alpha), proof)) === beta;
          return [alpha || '(empty)', ok ? 'match' : 'MISMATCH'];
        });
        return [
          row.table('Vectors', ['Input (hex)', 'Key, proof and output'], body),
          row.check('Every vector matches', body.every((r) => r[1] === 'match'), `${body.length} vectors`),
        ];
      },
    },
  ],
};
