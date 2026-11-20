import { row, mustRefuse } from '../kit.js';
import { same, hex, fromHex, concat, flipBit } from '../bytes.js';

const share = (bytes, k) => bytes.subarray(k * 32, k * 32 + 32);

function frostRound(cb, kg, signers, msg, alter) {
  const ids = signers.map((k) => k + 1);
  const commits = signers.map((k) => cb.call('frost_commit', share(kg.secret_shares, k), k + 1));
  const hiding = concat(...commits.map((c) => c.hiding_commit));
  const binding = concat(...commits.map((c) => c.binding_commit));
  const shares = signers.map((k, j) => cb.call('frost_sign', k + 1, share(kg.secret_shares, k), kg.group_public_key,
    commits[j].hiding_nonce, commits[j].binding_nonce, msg, ids, hiding, binding, ids.length));
  if (alter !== undefined) shares[alter] = flipBit(shares[alter], 0);
  const sig = cb.call('frost_aggregate', kg.group_public_key, msg, ids, hiding, binding, ids.length, concat(...shares));
  return { ids, commits, hiding, binding, shares, sig };
}

const rfc = {
  group: '15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673',
  msg: '74657374',
  s1: '929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509',
  s3: 'd3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02',
  h1: '812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407',
  b1: 'b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301',
  hc1: 'b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3',
  bc1: '67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932',
  h3: 'c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e',
  b3: '243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d',
  hc3: 'cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91',
  bc3: '7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552',
  ss1: '001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603',
  ss3: 'bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007',
  sig: '36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b',
};

export default {
  id: 'threshold',
  title: 'Threshold and aggregate signatures',
  lead: 'FROST splits one Ed25519 key so that any t of n holders can sign and fewer cannot. BLS12-381 goes the other way and folds many signatures into one.',
  demos: [
    {
      id: 'frost-sign',
      title: 'Two of three sign for the group',
      statement: 'A dealer splits a group key into three shares. Any two holders produce an ordinary Ed25519 signature that a verifier checks with no idea a threshold was involved.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'release payment 4411' },
        { name: 'pair', label: 'Signers', kind: 'select', value: '1 and 3', options: ['1 and 2', '1 and 3', '2 and 3'] },
      ],
      run(cb, { message, pair }) {
        const kg = cb.call('frost_keygen', 3, 2);
        const signers = pair.split(' and ').map((s) => Number(s) - 1);
        const r = frostRound(cb, kg, signers, message);
        const flow = [];
        r.commits.forEach((c, j) => flow.push(['round 1', `signer ${r.ids[j]}`, 'commitments', `${c.hiding_commit.length + c.binding_commit.length} bytes`]));
        r.shares.forEach((s, j) => flow.push(['round 2', `signer ${r.ids[j]}`, 'signature share', `${s.length} bytes`]));
        flow.push(['aggregate', 'coordinator', 'signature', `${r.sig.length} bytes`]);
        return [
          row.bytes('Group public key', kg.group_public_key),
          row.text('Shares dealt', `${kg.count} secret shares of 32 bytes, identifiers 1 to ${kg.count}`),
          row.table('Signing rounds', ['Round', 'From', 'Sends', 'Size'], flow),
          row.bytes('Aggregate signature', r.sig),
          row.check('frost_verify accepts it', cb.call('frost_verify', message, r.sig, kg.group_public_key) === 1, 'valid'),
          row.check('Plain ed25519_verify accepts it too', cb.call('ed25519_verify', message, r.sig, kg.group_public_key) === 1, 'valid Ed25519'),
          mustRefuse('The signature does not cover another message', () => cb.call('ed25519_verify', `${message}0`, r.sig, kg.group_public_key)),
        ];
      },
    },
    {
      id: 'frost-threshold',
      title: 'Any pair works, one alone does not',
      statement: 'Every two-signer subset of a 2-of-3 key yields a valid signature for the same group key. A single holder running the protocol alone gets a signature that does not verify.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'rotate the vault key' }],
      run(cb, { message }) {
        const kg = cb.call('frost_keygen', 3, 2);
        const pairs = [[0, 1], [0, 2], [1, 2]];
        const sigs = pairs.map((p) => frostRound(cb, kg, p, message).sig);
        const body = pairs.map((p, j) => [`${p[0] + 1} and ${p[1] + 1}`, hex(sigs[j]).slice(0, 24),
          cb.call('frost_verify', message, sigs[j], kg.group_public_key) === 1 ? 'valid' : 'invalid']);
        const solo = frostRound(cb, kg, [1], message).sig;
        return [
          row.table('Signatures by subset', ['Signers', 'Signature (start)', 'Verifies'], body),
          row.check('All three subsets sign for the same key', body.every((b) => b[2] === 'valid'), '3 of 3 valid'),
          row.check('Fresh nonces make each signature different', !same(sigs[0], sigs[1]) && !same(sigs[1], sigs[2]), 'distinct'),
          mustRefuse('Signer 2 alone cannot produce a valid signature', () => cb.call('frost_verify', message, solo, kg.group_public_key)),
          mustRefuse('A threshold larger than the group is refused', () => cb.call('frost_keygen', 2, 3)),
        ];
      },
    },
    {
      id: 'frost-cheater',
      title: 'Catching a cheating signer',
      statement: 'A bad share spoils the aggregate, but it does not have to stay anonymous. verify_share checks each share against its holder\'s public share and points at the one that was altered.',
      inputs: [
        { name: 'cheater', label: 'Signer who cheats', kind: 'select', value: '2', options: ['1', '2', '3'] },
      ],
      run(cb, { cheater }) {
        const kg = cb.call('frost_keygen', 3, 3);
        const message = 'approve the merger';
        const bad = Number(cheater) - 1;
        const r = frostRound(cb, kg, [0, 1, 2], message, bad);
        const body = r.ids.map((id, j) => {
          const ok = cb.call('frost_verify_share', id, share(kg.public_shares, id - 1), r.shares[j],
            r.commits[j].hiding_commit, r.commits[j].binding_commit, kg.group_public_key, message,
            r.ids, r.hiding, r.binding, r.ids.length);
          return [id, ok === 1 ? 'valid' : 'INVALID'];
        });
        const flagged = body.filter((b) => b[1] !== 'valid').map((b) => b[0]);
        return [
          row.text('Setup', '3-of-3 key; every share is needed'),
          row.table('Share checks', ['Signer', 'verify_share'], body),
          mustRefuse('The aggregate with the altered share does not verify', () => cb.call('frost_verify', message, r.sig, kg.group_public_key)),
          row.check('verify_share flags exactly the cheater', flagged.length === 1 && flagged[0] === bad + 1, `signer ${flagged.join(', ')}`),
        ];
      },
    },
    {
      id: 'frost-rfc',
      title: 'RFC 9591 known answer',
      statement: 'With the nonces fixed, FROST is fully deterministic. The engine reproduces the RFC 9591 FROST(Ed25519, SHA-512) vector from commitments to final signature.',
      inputs: [],
      run(cb) {
        const c1 = cb.call('frost_commit_with_nonces', 1, fromHex(rfc.h1), fromHex(rfc.b1));
        const c3 = cb.call('frost_commit_with_nonces', 3, fromHex(rfc.h3), fromHex(rfc.b3));
        const group = fromHex(rfc.group);
        const msg = fromHex(rfc.msg);
        const ids = [1, 3];
        const hiding = concat(c1.hiding_commit, c3.hiding_commit);
        const binding = concat(c1.binding_commit, c3.binding_commit);
        const s1 = cb.call('frost_sign', 1, fromHex(rfc.s1), group, c1.hiding_nonce, c1.binding_nonce, msg, ids, hiding, binding, 2);
        const s3 = cb.call('frost_sign', 3, fromHex(rfc.s3), group, c3.hiding_nonce, c3.binding_nonce, msg, ids, hiding, binding, 2);
        const sig = cb.call('frost_aggregate', group, msg, ids, hiding, binding, 2, concat(s1, s3));
        return [
          row.bytes('Signature', sig),
          row.check('Commitments match the vector',
            hex(c1.hiding_commit) === rfc.hc1 && hex(c1.binding_commit) === rfc.bc1
            && hex(c3.hiding_commit) === rfc.hc3 && hex(c3.binding_commit) === rfc.bc3, 'signers 1 and 3'),
          row.check('Signature shares match the vector', hex(s1) === rfc.ss1 && hex(s3) === rfc.ss3, 'both shares'),
          row.check('The aggregate signature matches the vector', hex(sig) === rfc.sig, 'known answer'),
          row.check('It verifies under the vector group key', cb.call('frost_verify', msg, sig, group) === 1, 'valid'),
        ];
      },
    },
    {
      id: 'bls-aggregate',
      title: 'Three signatures, one check',
      statement: 'Three BLS keys sign three different messages and the signatures fold into one of 96 bytes. One aggregate check covers all three, and it fails if any message changes.',
      inputs: [
        { name: 'a', label: 'First message', kind: 'text', value: 'block 1001 is valid' },
        { name: 'b', label: 'Second message', kind: 'text', value: 'block 1002 is valid' },
        { name: 'c', label: 'Third message', kind: 'text', value: 'block 1003 is valid' },
      ],
      run(cb, { a, b, c }) {
        const msgs = [a, b, c];
        const keys = msgs.map(() => cb.call('bls_keygen'));
        const sigs = msgs.map((m, k) => cb.call('bls_sign', m, keys[k].secret_key));
        const agg = cb.call('bls_aggregate', sigs);
        const pks = keys.map((k) => k.public_key);
        const body = msgs.map((m, k) => [k + 1, m, `${sigs[k].length} bytes`,
          cb.call('bls_verify', m, sigs[k], pks[k]) === 1 ? 'valid' : 'invalid']);
        const edited = [msgs[0], msgs[1], `${msgs[2]}!`];
        return [
          row.text('Key sizes', `${keys[0].secret_key.length}-byte secret, ${pks[0].length}-byte public (G1)`),
          row.table('Individual signatures', ['Signer', 'Message', 'Size', 'Verifies'], body),
          row.bytes('Aggregate signature', agg, `${sigs.length * 96} bytes of signatures in ${agg.length}`),
          row.check('Each signature verifies alone', body.every((r) => r[3] === 'valid'), 'three valid'),
          row.check('One aggregate check covers all three', cb.call('bls_aggregate_verify', msgs, pks, agg) === 1, 'valid'),
          mustRefuse('Changing one message breaks the aggregate', () => cb.call('bls_aggregate_verify', edited, pks, agg)),
          mustRefuse('A signature does not move to another message', () => cb.call('bls_verify', `${a}?`, sigs[0], pks[0])),
        ];
      },
    },
    {
      id: 'bls-ikm',
      title: 'Keys from seed material',
      statement: 'bls_keygen_from_ikm derives a key deterministically from at least 32 bytes of input keying material. BLS signing is deterministic too, so the same key and message always give the same signature.',
      inputs: [{ name: 'seed', label: 'Seed phrase', kind: 'text', value: 'validator 17 backup seed, keep offline' }],
      run(cb, { seed }) {
        const ikm = cb.call('sha256', seed);
        const k1 = cb.call('bls_keygen_from_ikm', ikm);
        const k2 = cb.call('bls_keygen_from_ikm', ikm);
        const other = cb.call('bls_keygen_from_ikm', cb.call('sha256', `${seed}.`));
        const short = cb.call('bls_keygen_from_ikm', ikm.subarray(0, 16));
        const s1 = cb.call('bls_sign', 'epoch 9', k1.secret_key);
        const s2 = cb.call('bls_sign', 'epoch 9', k2.secret_key);
        return [
          row.bytes('Input keying material (SHA-256 of the phrase)', ikm),
          row.bytes('Public key', k1.public_key),
          row.check('Same material, same key', same(k1.public_key, k2.public_key) && same(k1.secret_key, k2.secret_key), 'identical'),
          row.check('Other material, unrelated key', !same(k1.public_key, other.public_key), 'distinct'),
          row.check('Same key and message, same signature', same(s1, s2), 'deterministic'),
          row.check('Material under 32 bytes yields no key', short.public_key.length === 0 && short.secret_key.length === 0, 'empty key pair'),
        ];
      },
    },
  ],
};
