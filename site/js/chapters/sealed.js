import { row, mustRefuse, timed } from '../kit.js';
import { hex, same, utf8, concat, flipBit } from '../bytes.js';

const TIERS = { Flagship: 0, Fortress: 1 };
const SUITE_NAMES = { 1: 'Flagship', 2: 'Fortress' };

function parseShares(blob) {
  const shares = [];
  let at = 0;
  while (at < blob.length) {
    const ylen = new DataView(blob.buffer, blob.byteOffset + at + 1, 4).getUint32(0, true);
    shares.push({ index: blob[at], record: blob.subarray(at, at + 5 + ylen) });
    at += 5 + ylen;
  }
  return shares;
}

function keyFile(seed) {
  const out = new Uint8Array(4096);
  for (let i = 0; i < out.length; i++) out[i] = (i * 37 + seed) & 0xff;
  return out;
}

export default {
  id: 'sealed',
  title: 'Sealed messaging',
  lead: 'Post-quantum envelopes that encrypt to a recipient and sign as the sender in one call. Flagship and Fortress are the two tiers of the sealed construction; Suite v1 and Suite v2 are the one-call combinations around them.',
  demos: [
    {
      id: 'one-shot',
      title: 'Seal to one recipient, signed by one sender',
      statement: 'Flagship encapsulates with X25519 plus sntrup761 and signs with Ed25519 plus ML-DSA-65; Fortress adds ML-KEM-768 and SLH-DSA. Opening checks the sender and the intended recipient before any plaintext is released.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'textarea', value: 'The board approves the merger. Announce on Monday.' },
        { name: 'tier', label: 'Tier', kind: 'select', value: 'Flagship', options: ['Flagship', 'Fortress'] },
      ],
      run(cb, { message, tier }) {
        const t = TIERS[tier];
        const alice = cb.call('sealed_generate_recipient', t);
        const bob = cb.call('sealed_generate_recipient', t);
        const sender = cb.call('sealed_generate_sender', t);
        const mallory = cb.call('sealed_generate_sender', t);
        const aad = utf8.encode('board/2026-11');
        const purpose = utf8.encode('board-minutes');
        const sealed = timed(() => cb.call('sealed_seal', t, message, alice.public_key, sender.secret_key, aad, purpose));
        const env = sealed.value;
        const open = (e, rsk, rpk, spk, a = aad, p = purpose) => cb.call('sealed_open', t, e, rsk, rpk, spk, a, p);
        const opened = timed(() => open(env, alice.secret_key, alice.public_key, sender.public_key));
        return [
          row.text('Key sizes', `recipient public ${alice.public_key.length} B, sender public ${sender.public_key.length} B`),
          row.bytes('Envelope', env.subarray(0, 64), `first 64 of ${env.length} bytes`),
          row.text('Time', `seal ${sealed.ms.toFixed(0)} ms, open ${opened.ms.toFixed(0)} ms`),
          row.check('Alice opens it', utf8.decode(opened.value) === message, utf8.decode(opened.value)),
          mustRefuse('Bob, with his own keys, is refused', () => open(env, bob.secret_key, bob.public_key, sender.public_key)),
          mustRefuse('A forged sender key is refused', () => open(env, alice.secret_key, alice.public_key, mallory.public_key)),
          mustRefuse('Alice cannot pass it off as addressed to Bob',
            () => open(env, alice.secret_key, bob.public_key, sender.public_key)),
          mustRefuse('One flipped bit in the envelope is refused',
            () => open(flipBit(env, -1), alice.secret_key, alice.public_key, sender.public_key)),
          mustRefuse('Another purpose label is refused',
            () => open(env, alice.secret_key, alice.public_key, sender.public_key, aad, 'payroll')),
        ];
      },
    },
    {
      id: 'inspect',
      title: 'Read the label without opening',
      statement: 'An envelope carries its version, suite and a 16-byte fingerprint of the recipient key in the clear. A mail server can route it, and a recipient can tell whether it is theirs, without any secret key.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'quarterly figures attached' }],
      run(cb, { message }) {
        const alice = cb.call('sealed_generate_recipient', 0);
        const carol = cb.call('sealed_generate_recipient', 0);
        const sender = cb.call('sealed_generate_sender', 0);
        const env = cb.call('sealed_seal', 0, message, alice.public_key, sender.secret_key, null, null);
        const info = cb.call('sealed_inspect', env);
        const expected = cb.call('blake2b', alice.public_key, null).subarray(0, 16);
        const fortR = cb.call('sealed_generate_recipient', 1);
        const fortS = cb.call('sealed_generate_sender', 1);
        const fort = cb.call('sealed_seal', 1, message, fortR.public_key, fortS.secret_key, null, null);
        const fortInfo = cb.call('sealed_inspect', fort);
        const junk = cb.call('sealed_inspect', utf8.encode('not an envelope at all'));
        return [
          row.table('Public header', ['Field', 'Flagship envelope', 'Fortress envelope'], [
            ['version', String(info.version), String(fortInfo.version)],
            ['suite', SUITE_NAMES[info.suite] || String(info.suite), SUITE_NAMES[fortInfo.suite] || String(fortInfo.suite)],
            ['streaming', info.streaming ? 'yes' : 'no', fortInfo.streaming ? 'yes' : 'no'],
            ['KEM ciphertext', `${info.kem_ciphertext_len} B`, `${fortInfo.kem_ciphertext_len} B`],
            ['envelope size', `${env.length} B`, `${fort.length} B`],
          ]),
          row.bytes('Recipient fingerprint', info.fingerprint),
          row.check('The fingerprint is BLAKE2b of Alice\'s public key', same(info.fingerprint, expected), 'first 16 bytes'),
          row.check('Header reads version 1, suites Flagship and Fortress',
            info.ok === 1 && info.version === 1 && info.suite === 1 && fortInfo.suite === 2, 'parsed'),
          row.check('Addressed to Alice', cb.call('sealed_addressed_to', env, alice.public_key) === 1, 'yes'),
          mustRefuse('Not addressed to Carol', () => cb.call('sealed_addressed_to', env, carol.public_key)),
          row.check('Arbitrary bytes are not an envelope', junk.ok === 0, 'ok = 0'),
          mustRefuse('A Fortress envelope does not open as Flagship',
            () => cb.call('sealed_open', 0, fort, alice.secret_key, alice.public_key, sender.public_key, null, null)),
        ];
      },
    },
    {
      id: 'stream',
      title: 'Seal a stream chunk by chunk',
      statement: 'A large message is sealed as a preamble, a run of chunks and a signed trailer, and opened one chunk at a time. Drop the final chunk and the opener refuses to confirm the stream.',
      inputs: [
        { name: 'text', label: 'Message', kind: 'textarea', value: 'Chapter one arrives first. Chapter two follows a moment later. The last chapter closes the stream and carries the end marker.' },
        { name: 'chunk', label: 'Chunk size (bytes)', kind: 'number', value: 40, min: 4, max: 4096 },
      ],
      run(cb, { text, chunk }) {
        const data = utf8.encode(text);
        const step = Math.max(1, Number(chunk));
        const alice = cb.call('sealed_generate_recipient', 0);
        const sender = cb.call('sealed_generate_sender', 0);
        const mallory = cb.call('sealed_generate_sender', 0);
        const purpose = utf8.encode('chapter-feed');
        const pieces = [];
        for (let i = 0; i < data.length; i += step) pieces.push(data.subarray(i, i + step));
        if (!pieces.length) pieces.push(new Uint8Array(0));
        const wire = [];
        let preamble;
        let trailer;
        let last;
        const s = cb.call('sealed_sealer_begin', 0, alice.public_key, sender.secret_key, purpose);
        try {
          preamble = cb.call('sealed_sealer_preamble', s);
          for (const p of pieces.slice(0, -1)) wire.push(cb.call('sealed_sealer_push', s, p));
          const out = cb.Out.buffer();
          last = cb.call('sealed_sealer_finalize', s, pieces[pieces.length - 1], out);
          trailer = out.value;
        } finally {
          cb.call('sealed_sealer_free', s);
        }
        const openWith = (spk, chunks) => {
          const o = cb.call('sealed_opener_begin', 0, preamble, alice.secret_key, alice.public_key, spk, purpose);
          try {
            const parts = [];
            const finals = [];
            for (const c of chunks) {
              const flag = cb.Out.scalar();
              parts.push(cb.call('sealed_opener_pull', o, c, flag));
              finals.push(flag.value);
            }
            cb.call('sealed_opener_finalize', o, trailer);
            return { text: utf8.decode(concat(...parts)), finals };
          } finally {
            cb.call('sealed_opener_free', o);
          }
        };
        const opened = openWith(sender.public_key, [...wire, last]);
        const info = cb.call('sealed_inspect', preamble);
        return [
          row.text('Chunks on the wire', `${wire.length + 1} (${pieces.length - 1} pushed, 1 final)`),
          row.bytes('Preamble', preamble.subarray(0, 48), `first 48 of ${preamble.length} bytes`),
          row.bytes('Signed trailer', trailer.subarray(0, 48), `first 48 of ${trailer.length} bytes`),
          row.check('The preamble inspects as a streaming envelope', info.ok === 1 && info.streaming === 1, 'streaming'),
          row.check('Only the last chunk is marked final', opened.finals.every((f, i) => f === (i === opened.finals.length - 1 ? 1 : 0)),
            opened.finals.join(' ')),
          row.check('Chunks reassemble to the message', opened.text === text, `${data.length} bytes`),
          mustRefuse('A stream cut before its final chunk is refused', () => openWith(sender.public_key, wire)),
          mustRefuse('A stream checked against another sender is refused', () => openWith(mallory.public_key, [...wire, last])),
          wire.length
            ? mustRefuse('Chunks out of order are refused',
              () => openWith(sender.public_key, wire.length > 1 ? [wire[1], wire[0], ...wire.slice(2), last] : [last, wire[0]]))
            : row.text('Chunks out of order', 'one chunk only, nothing to reorder'),
        ];
      },
    },
    {
      id: 'suite-pq',
      title: 'Suite v1: post-quantum envelopes',
      statement: 'seal_pq encrypts to an X25519 plus ML-KEM-768 key, or an X25519 plus sntrup761 key, and open_pq picks the KEM from the envelope. The signed variants add an Ed25519 plus ML-DSA-65 signature checked before release.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'transfer 100 to account 42' }],
      run(cb, { message }) {
        const aad = utf8.encode('suite/v1');
        const mlkem = cb.call('hybrid_kem_keygen');
        const sntrup = cb.call('sntrup_x25519_keygen');
        const signer = cb.call('hybrid_sig_keygen');
        const impostor = cb.call('hybrid_sig_keygen');
        const envA = cb.call('suite_seal_pq', message, mlkem.public_key, aad);
        const envB = cb.call('suite_seal_pq_sntrup', message, sntrup.public_key, aad);
        const signedA = cb.call('suite_seal_signed_pq', message, mlkem.public_key, signer.secret_key, aad);
        const signedB = cb.call('suite_seal_signed_pq_sntrup', message, sntrup.public_key, signer.secret_key, aad);
        const openSigned = (env, sk, spk) => utf8.decode(cb.call('suite_open_signed_pq', env, sk, spk, aad));
        return [
          row.table('Envelopes', ['Call', 'Suite id', 'Size'], [
            ['suite_seal_pq', `0x${hex(envA.subarray(5, 6))}`, `${envA.length} B`],
            ['suite_seal_pq_sntrup', `0x${hex(envB.subarray(5, 6))}`, `${envB.length} B`],
            ['suite_seal_signed_pq', `0x${hex(signedA.subarray(5, 6))}`, `${signedA.length} B`],
            ['suite_seal_signed_pq_sntrup', `0x${hex(signedB.subarray(5, 6))}`, `${signedB.length} B`],
          ], 'the suite id is header byte 5'),
          row.check('open_pq opens both KEM families', utf8.decode(cb.call('suite_open_pq', envA, mlkem.secret_key, aad)) === message
            && utf8.decode(cb.call('suite_open_pq', envB, sntrup.secret_key, aad)) === message, 'ML-KEM and sntrup761'),
          row.check('open_signed_pq opens both signed envelopes', openSigned(signedA, mlkem.secret_key, signer.public_key) === message
            && openSigned(signedB, sntrup.secret_key, signer.public_key) === message, 'signature valid'),
          mustRefuse('An ML-KEM key cannot open a sntrup envelope', () => cb.call('suite_open_pq', envB, mlkem.secret_key, aad)),
          mustRefuse('Another AAD is refused', () => cb.call('suite_open_pq', envA, mlkem.secret_key, 'suite/v0')),
          mustRefuse('A different sender key is refused', () => openSigned(signedA, mlkem.secret_key, impostor.public_key)),
          mustRefuse('A signed envelope does not open as an unsigned one', () => cb.call('suite_open_pq', signedA, mlkem.secret_key, aad)),
        ];
      },
    },
    {
      id: 'local-keys',
      title: 'Suite v1: a file or a keyring as the key',
      statement: 'seal_with_file derives the key from the bytes of a file, so the same file opens it and any other file does not. The keyring calls take the key from a keyring slot, so a device key and a passphrase unlock the same envelopes.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'recovery seed for the cold wallet' },
        { name: 'passphrase', label: 'Keyring passphrase', kind: 'text', value: 'cross device pass' },
      ],
      run(cb, { message, passphrase }) {
        const aad = utf8.encode('suite/v1');
        const pathA = cb.writeFile('/demo/keys/holiday-photo.bin', keyFile(11));
        const pathB = cb.writeFile('/demo/keys/other-photo.bin', keyFile(12));
        const fileEnv = cb.call('suite_seal_with_file', message, pathA, aad);
        const fromFile = utf8.decode(cb.call('suite_open_with_file', fileEnv, pathA, aad));
        const device = cb.call('random_bytes', 32);
        const wrong = cb.call('random_bytes', 32);
        const kr = cb.call('keyring_create');
        try {
          cb.call('keyring_add_device_slot', kr, device);
          cb.call('keyring_add_passphrase_slot', kr, passphrase, 0);
          const byDevice = cb.call('suite_seal_with_keyring_device', message, kr, device, aad);
          const byPass = cb.call('suite_seal_with_keyring_passphrase', message, kr, passphrase, aad);
          const viaPass = utf8.decode(cb.call('suite_open_with_keyring_passphrase', byDevice, kr, passphrase, aad));
          const viaDevice = utf8.decode(cb.call('suite_open_with_keyring_device', byPass, kr, device, aad));
          return [
            row.text('Key file', `${pathA} (4096 bytes in the engine's memory file system)`),
            row.bytes('Envelope sealed with the file', fileEnv.subarray(0, 48), `first 48 of ${fileEnv.length} bytes`),
            row.check('The same file opens it', fromFile === message, fromFile),
            mustRefuse('Another file is refused', () => cb.call('suite_open_with_file', fileEnv, pathB, aad)),
            row.text('Keyring slots', String(cb.call('keyring_slot_count', kr)), 'one device key, one passphrase'),
            row.check('Sealed with the device key, opened with the passphrase', viaPass === message, viaPass),
            row.check('Sealed with the passphrase, opened with the device key', viaDevice === message, viaDevice),
            mustRefuse('A wrong device key is refused', () => cb.call('suite_open_with_keyring_device', byDevice, kr, wrong, aad)),
            mustRefuse('A wrong passphrase is refused',
              () => cb.call('suite_open_with_keyring_passphrase', byDevice, kr, `${passphrase}!`, aad)),
          ];
        } finally {
          cb.call('keyring_free', kr);
        }
      },
    },
    {
      id: 'threshold',
      title: 'Suite v1: any three of five',
      statement: 'seal_threshold seals under a fresh key and splits that key into Shamir shares. Any quorum of shares opens the envelope; one share short and it stays shut.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'vault combination 31-07-44' },
        { name: 'n', label: 'Shares (n)', kind: 'number', value: 5, min: 2, max: 10 },
        { name: 'k', label: 'Quorum (k)', kind: 'number', value: 3, min: 2, max: 10 },
      ],
      run(cb, { message, n, k }) {
        const aad = utf8.encode('suite/v1');
        const total = Number(n);
        const quorum = Math.min(Number(k), total);
        const out = cb.Out.buffer();
        const env = cb.call('suite_seal_threshold', message, total, quorum, aad, out);
        const shares = parseShares(out.value);
        const pick = (list) => concat(...list.map((s) => s.record));
        const first = shares.slice(0, quorum);
        const last = shares.slice(total - quorum);
        const open = (list) => utf8.decode(cb.call('suite_open_threshold', env, pick(list), aad));
        return [
          row.table('Shares', ['Index', 'Share'], shares.map((s) => [String(s.index), hex(s.record.subarray(5))])),
          row.check(`Shares 1 to ${quorum} open it`, open(first) === message, open(first)),
          row.check(`Shares ${total - quorum + 1} to ${total} open it too`, open(last) === message, 'any quorum'),
          mustRefuse(`${quorum - 1} shares are refused`, () => open(shares.slice(0, quorum - 1))),
          mustRefuse('A quorum with one altered share is refused',
            () => open([...first.slice(0, -1), { record: flipBit(first[quorum - 1].record, -1) }])),
          mustRefuse('A quorum larger than the share count is refused',
            () => cb.call('suite_seal_threshold', message, 3, 5, aad, cb.Out.buffer())),
        ];
      },
    },
    {
      id: 'suite2',
      title: 'Suite v2: signatures bound to the recipient',
      statement: 'A v2 envelope signs the recipient key, the KEM ciphertext and the AAD along with the message, so a signed message cannot be re-sealed to someone else. suite_of names the suite from the header.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'wire 100 EUR' }],
      run(cb, { message }) {
        const aad = utf8.encode('ctx');
        const bob = cb.call('xwing_keygen');
        const carol = cb.call('xwing_keygen');
        const alice = cb.call('hybrid_sig_keygen');
        const mallory = cb.call('hybrid_sig_keygen');
        const env = cb.call('suite2_seal', message, bob.public_key, alice.secret_key, aad, 0x11);
        const open = (e, r, spk, a = aad) => cb.call('suite2_open', e, r.secret_key, r.public_key, spk, a);
        const opened = utf8.decode(open(env, bob, alice.public_key));
        const v1 = cb.call('suite_seal_pq', message, cb.call('hybrid_kem_keygen').public_key, aad);
        const native = cb.call('hybrid_kem_keygen');
        let nativeRow;
        try {
          const env12 = cb.call('suite2_seal', message, native.public_key, alice.secret_key, aad, 0x12);
          nativeRow = row.check('Suite 0x12 (X25519 plus ML-KEM-768) round-trips',
            cb.call('suite2_suite_of', env12) === 0x12 && utf8.decode(open(env12, native, alice.public_key)) === message, '0x12');
        } catch (error) {
          nativeRow = row.text('Suite 0x12', `not in this build: ${error.message}`);
        }
        return [
          row.bytes('Envelope', env.subarray(0, 48), `first 48 of ${env.length} bytes`),
          row.text('suite_of', `0x${cb.call('suite2_suite_of', env).toString(16)} (X-Wing, signed)`),
          row.check('Bob opens it', opened === message, opened),
          row.check('suite_of is 0x11 for X-Wing and 0 for a v1 envelope',
            cb.call('suite2_suite_of', env) === 0x11 && cb.call('suite2_suite_of', v1) === 0, '0x11, then 0'),
          nativeRow,
          mustRefuse('Carol cannot open it', () => open(env, carol, alice.public_key)),
          mustRefuse('A different sender key is refused', () => open(env, bob, mallory.public_key)),
          mustRefuse('Bob cannot present it as sent to Carol',
            () => cb.call('suite2_open', env, bob.secret_key, carol.public_key, alice.public_key, aad)),
          mustRefuse('Another AAD is refused', () => open(env, bob, alice.public_key, 'other')),
        ];
      },
    },
  ],
};
