import { row, mustRefuse, timed, bitDistance } from '../kit.js';
import { hex, fromHex, same, utf8, flipBit } from '../bytes.js';

const KDF = { 'HKDF-SHA256': 1, 'HKDF-SHA512': 3 };
const AEAD = { 'ChaCha20-Poly1305': 3, 'AES-128-GCM': 1, 'AES-256-GCM': 2 };
const EXPORT_ONLY = 65535;
const MODE = { base: 0, psk: 1, auth: 2, authPsk: 3 };
const KEMS = [
  ['DHKEM(X25519, HKDF-SHA256)', 0x0020],
  ['ML-KEM-768', 0x0041],
  ['X-Wing', 0x647a],
];

const RFC9180_A2 = {
  info: '4f6465206f6e2061204772656369616e2055726e',
  ikmE: '909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b',
  ikmR: '1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df',
  skRm: '8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb',
  pkRm: '4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a',
  enc: '1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a',
  aad0: '436f756e742d30',
  pt: '4265617574792069732074727574682c20747275746820626561757479',
  ct0: '1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28',
  exportEmpty: '4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e',
  exportTest: '5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53',
};

function setupS(cb, o, enc) {
  if (o.kem == null) {
    return cb.call('hpke_setup_s', o.kdf ?? 1, o.aead ?? 3, o.mode ?? 0, o.pkR, o.info, o.psk, o.pskId, o.skS, enc);
  }
  return cb.call('hpke_setup_s_kem', o.kem, o.kdf ?? 1, o.aead ?? 3, o.mode ?? 0, o.pkR, o.info, o.psk, o.pskId, o.skS, enc);
}

function setupR(cb, o, enc) {
  if (o.kem == null) {
    return cb.call('hpke_setup_r', o.kdf ?? 1, o.aead ?? 3, o.mode ?? 0, enc, o.skR, o.info, o.psk, o.pskId, o.pkS);
  }
  return cb.call('hpke_setup_r_kem', o.kem, o.kdf ?? 1, o.aead ?? 3, o.mode ?? 0, enc, o.skR, o.info, o.psk, o.pskId, o.pkS);
}

/** Sets up a sender and a receiver context (receiver options override sender ones), runs fn, then frees both. */
function withPair(cb, sender, receiver, fn) {
  const handles = [];
  try {
    const enc = cb.Out.buffer();
    const s = setupS(cb, sender, enc);
    handles.push(s);
    const r = setupR(cb, { ...sender, ...receiver }, enc.value);
    handles.push(r);
    return fn(s, r, enc.value);
  } finally {
    for (const h of handles) cb.call('hpke_context_free', h);
  }
}

/** A check that a sender setup is refused; a context made by mistake is freed. */
function refuseSetup(cb, label, o) {
  return mustRefuse(label, () => {
    const h = setupS(cb, o, cb.Out.buffer());
    cb.call('hpke_context_free', h);
    return h;
  });
}

export default {
  id: 'hpke',
  title: 'HPKE: encrypt to a public key',
  lead: 'Hybrid Public Key Encryption (RFC 9180), the standard behind TLS Encrypted Client Hello, MLS and Oblivious HTTP. A key encapsulation sets up a one-way channel, and both ends can export shared secrets from it.',
  demos: [
    {
      id: 'base',
      title: 'Seal to a public key',
      statement: 'The sender needs only the recipient public key and sends a 32-byte encapsulation with the first message. The info string binds both sides to one context, so a mismatch is refused.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'quarterly figures, board only' },
        { name: 'aead', label: 'Cipher', kind: 'select', value: 'ChaCha20-Poly1305', options: Object.keys(AEAD) },
        { name: 'kdf', label: 'Key derivation', kind: 'select', value: 'HKDF-SHA256', options: Object.keys(KDF) },
      ],
      run(cb, { message, aead, kdf }) {
        const bob = cb.call('hpke_keygen');
        const eve = cb.call('hpke_keygen');
        const o = { kdf: KDF[kdf], aead: AEAD[aead], mode: MODE.base, pkR: bob.public_key, skR: bob.secret_key, info: 'demo app v1' };
        const out = withPair(cb, o, {}, (s, r, enc) => {
          const ct = cb.call('hpke_seal', s, 'header', message);
          const opened = utf8.decode(cb.call('hpke_open', r, 'header', ct));
          const exportS = cb.call('hpke_export', s, 'file key', 32);
          const exportR = cb.call('hpke_export', r, 'file key', 32);
          return [
            row.bytes('Encapsulation (enc)', enc),
            row.bytes('Ciphertext', ct),
            row.text('Overhead', `${enc.length} bytes of enc once, then ${ct.length - utf8.encode(message).length} bytes of tag per message`),
            row.check('Bob opens it', opened === message, opened),
            row.check('Both sides export the same secret', same(exportS, exportR), hex(exportS).slice(0, 16)),
            mustRefuse('Edited associated data is refused', () => cb.call('hpke_open', r, 'header2', cb.call('hpke_seal', s, 'header', message))),
          ];
        });
        const wrongInfo = withPair(cb, o, { info: 'demo app v2' }, (s, r) => mustRefuse('A receiver with another info string cannot open it',
          () => cb.call('hpke_open', r, 'header', cb.call('hpke_seal', s, 'header', message))));
        const wrongKey = withPair(cb, o, { skR: eve.secret_key }, (s, r) => mustRefuse('Another secret key cannot open it',
          () => cb.call('hpke_open', r, 'header', cb.call('hpke_seal', s, 'header', message))));
        return [...out, wrongInfo, wrongKey];
      },
    },
    {
      id: 'order',
      title: 'Messages open in order',
      statement: 'Each message uses the next nonce in a sequence, so the receiver must open them in the order they were sealed. A message out of turn or a replay is refused, and a refusal does not move the counter.',
      inputs: [],
      run(cb) {
        const bob = cb.call('hpke_keygen');
        const o = { mode: MODE.base, pkR: bob.public_key, skR: bob.secret_key, info: 'ordered channel' };
        return withPair(cb, o, {}, (s, r) => {
          const parts = ['pay 10', 'pay 10', 'stop'];
          const sealed = parts.map((p) => cb.call('hpke_seal', s, null, p));
          const early = mustRefuse('Opening the second message first is refused', () => cb.call('hpke_open', r, null, sealed[1]));
          const opened = sealed.map((c) => utf8.decode(cb.call('hpke_open', r, null, c)));
          const apart = bitDistance(sealed[0], sealed[1]);
          return [
            row.text('Sealed', parts.join(', ')),
            row.bytes('Message 1', sealed[0]),
            row.bytes('Message 2, same text', sealed[1]),
            row.check('The same text sealed twice gives unrelated ciphertexts', apart > 40, `${apart} of ${sealed[0].length * 8} bits differ`),
            early,
            row.check('After that refusal, all three open in order', opened.join(',') === parts.join(','), opened.join(', ')),
            mustRefuse('Replaying the first message is refused', () => cb.call('hpke_open', r, null, sealed[0])),
          ];
        });
      },
    },
    {
      id: 'kat',
      title: 'The RFC 9180 test vector',
      statement: 'This replays appendix A.2 of RFC 9180 (X25519, HKDF-SHA256, ChaCha20-Poly1305). The engine derives the published keys, opens the published ciphertext and exports the published secrets.',
      inputs: [],
      run(cb) {
        const v = RFC9180_A2;
        const recipient = cb.call('hpke_derive_keypair', fromHex(v.ikmR));
        const ephemeral = cb.call('hpke_derive_keypair', fromHex(v.ikmE));
        const viaKem = cb.call('hpke_derive_keypair_kem', 0x0020, fromHex(v.ikmR));
        const r = cb.call('hpke_setup_r', 1, 3, MODE.base, fromHex(v.enc), recipient.secret_key, fromHex(v.info), null, null, null);
        try {
          const pt = cb.call('hpke_open', r, fromHex(v.aad0), fromHex(v.ct0));
          return [
            row.text('Plaintext', utf8.decode(pt)),
            row.check('DeriveKeyPair(ikmR) gives skRm and pkRm', hex(recipient.secret_key) === v.skRm && hex(recipient.public_key) === v.pkRm, 'known answer'),
            row.check('DeriveKeyPair(ikmE) gives the published enc', hex(ephemeral.public_key) === v.enc, 'known answer'),
            row.check('The KEM-selectable call derives the same pair', same(viaKem.public_key, recipient.public_key) && same(viaKem.secret_key, recipient.secret_key), 'identical'),
            row.check('Message 0 opens to the published plaintext', hex(pt) === v.pt, 'known answer'),
            row.check('Export with an empty context', hex(cb.call('hpke_export', r, new Uint8Array(0), 32)) === v.exportEmpty, 'known answer'),
            row.check('Export with context "TestContext"', hex(cb.call('hpke_export', r, 'TestContext', 32)) === v.exportTest, 'known answer'),
          ];
        } finally {
          cb.call('hpke_context_free', r);
        }
      },
    },
    {
      id: 'modes',
      title: 'Pre-shared keys and sender authentication',
      statement: 'PSK mode mixes in a shared secret, auth mode proves the sender held a known key pair, and auth-PSK does both. A wrong PSK or sender key derives other keys, so the first message is refused.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'payroll run approved' }],
      run(cb, { message }) {
        const bob = cb.call('hpke_keygen');
        const alice = cb.call('hpke_keygen');
        const mallory = cb.call('hpke_keygen');
        const psk = cb.call('random_bytes', 32);
        const pskId = 'payroll-2026';
        const base = { pkR: bob.public_key, skR: bob.secret_key, info: 'modes demo' };
        const roundTrip = (o, r = {}) => withPair(cb, { ...base, ...o }, r, (s, rc) => utf8.decode(cb.call('hpke_open', rc, null, cb.call('hpke_seal', s, null, message))));
        const refused = (label, o, r) => mustRefuse(label, () => roundTrip(o, r));
        const pskMode = { mode: MODE.psk, psk, pskId };
        const authMode = { mode: MODE.auth, skS: alice.secret_key, pkS: alice.public_key };
        const both = { mode: MODE.authPsk, psk, pskId, skS: alice.secret_key, pkS: alice.public_key };
        return [
          row.table('Modes', ['Mode', 'Id', 'Sender adds', 'Receiver adds'], [
            ['base', 0, 'nothing', 'nothing'],
            ['psk', 1, 'psk, psk_id', 'psk, psk_id'],
            ['auth', 2, 'own secret key', 'sender public key'],
            ['auth-psk', 3, 'both', 'both'],
          ]),
          row.check('PSK mode opens with the same PSK', roundTrip(pskMode) === message, 'opened'),
          refused('PSK mode with another PSK is refused', pskMode, { psk: cb.call('random_bytes', 32) }),
          refuseSetup(cb, 'PSK mode without a PSK is refused at setup', { ...base, mode: MODE.psk }),
          row.check('Auth mode opens with the sender public key', roundTrip(authMode) === message, 'opened'),
          refused('Auth mode checked against Mallory public key is refused', authMode, { pkS: mallory.public_key }),
          refused('Mallory sealing as herself cannot pass for Alice', { ...authMode, skS: mallory.secret_key }, { pkS: alice.public_key }),
          row.check('Auth-PSK mode opens with both', roundTrip(both) === message, 'opened'),
          refused('Auth-PSK with the right sender but another PSK is refused', both, { psk: cb.call('random_bytes', 32) }),
        ];
      },
    },
    {
      id: 'export-only',
      title: 'Export-only: HPKE as key agreement',
      statement: 'With the export-only cipher a context encrypts nothing and only derives secrets. Sender and receiver get the same key for any label, a different key per label.',
      inputs: [
        { name: 'label', label: 'Exporter context', kind: 'text', value: 'video call key' },
        { name: 'length', label: 'Length (bytes)', kind: 'number', value: 32, min: 1, max: 255 },
      ],
      run(cb, { label, length }) {
        const bob = cb.call('hpke_keygen');
        const n = Number(length);
        const o = { aead: EXPORT_ONLY, mode: MODE.base, pkR: bob.public_key, skR: bob.secret_key, info: 'export only' };
        return withPair(cb, o, {}, (s, r) => {
          const a = cb.call('hpke_export', s, label, n);
          const b = cb.call('hpke_export', r, label, n);
          const other = cb.call('hpke_export', r, `${label}/2`, n);
          return [
            row.bytes('Sender export', a),
            row.bytes('Receiver export', b),
            row.check('Both sides export the same secret', same(a, b) && a.length === n, `${a.length} bytes`),
            row.check('Another label gives another secret', !same(a, other), 'different'),
            mustRefuse('Sealing is refused', () => cb.call('hpke_seal', s, null, 'hello')),
          ];
        });
      },
    },
    {
      id: 'pq-kems',
      title: 'Post-quantum HPKE',
      statement: 'The same HPKE runs over ML-KEM-768 or X-Wing from the draft-ietf-hpke-pq code points. A KEM has no sender authentication, so these suites offer base and PSK modes only.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'archive this for thirty years' }],
      run(cb, { message }) {
        const rows = [];
        const checks = [];
        const ikm = cb.call('sha256', 'hpke pq demo ikm');
        for (const [name, kem] of KEMS) {
          if (cb.call('hpke_kem_available', kem) !== 1) {
            rows.push([name, `0x${kem.toString(16).padStart(4, '0')}`, 'not in this build', '', '', '']);
            continue;
          }
          const bob = cb.call('hpke_keygen_kem', kem);
          const other = cb.call('hpke_keygen_kem', kem);
          const o = { kem, mode: MODE.base, pkR: bob.public_key, skR: bob.secret_key, info: 'pq demo' };
          const t = timed(() => withPair(cb, o, {}, (s, r, enc) => {
            const opened = utf8.decode(cb.call('hpke_open', r, null, cb.call('hpke_seal', s, null, message)));
            return { enc, opened, agree: same(cb.call('hpke_export', s, 'x', 32), cb.call('hpke_export', r, 'x', 32)) };
          }));
          const res = t.value;
          rows.push([name, `0x${kem.toString(16).padStart(4, '0')}`, bob.public_key.length, bob.secret_key.length, res.enc.length, `${t.ms.toFixed(1)} ms`]);
          checks.push(row.check(`${name}: opens and exports agree`, res.opened === message && res.agree, 'round trip'));
          const d1 = cb.call('hpke_derive_keypair_kem', kem, ikm);
          const d2 = cb.call('hpke_derive_keypair_kem', kem, ikm);
          checks.push(row.check(`${name}: DeriveKeyPair is deterministic`, same(d1.public_key, d2.public_key) && same(d1.secret_key, d2.secret_key), 'identical'));
          checks.push(withPair(cb, o, { skR: other.secret_key }, (s, r) => mustRefuse(`${name}: another secret key cannot open it`,
            () => cb.call('hpke_open', r, null, cb.call('hpke_seal', s, null, message)))));
          if (kem !== 0x0020) {
            const alice = cb.call('hpke_keygen');
            checks.push(refuseSetup(cb, `${name}: auth mode is refused`, { ...o, mode: MODE.auth, skS: alice.secret_key }));
            const psk = cb.call('random_bytes', 32);
            const pskOpened = withPair(cb, { ...o, mode: MODE.psk, psk, pskId: 'pq' }, {},
              (s, r) => utf8.decode(cb.call('hpke_open', r, null, cb.call('hpke_seal', s, null, message))));
            checks.push(row.check(`${name}: PSK mode works`, pskOpened === message, 'opened'));
          }
        }
        return [
          row.table('KEMs (bytes)', ['KEM', 'Id', 'Public key', 'Secret key', 'enc', 'Setup and one message'], rows,
            'The post-quantum secret keys are seeds; the expanded keys are rebuilt from them.'),
          ...checks,
          mustRefuse('A tampered X-Wing encapsulation cannot open the message', () => {
            const bob = cb.call('hpke_keygen_kem', 0x647a);
            const enc = cb.Out.buffer();
            const s = setupS(cb, { kem: 0x647a, pkR: bob.public_key, info: 'pq demo' }, enc);
            let r = 0;
            try {
              const ct = cb.call('hpke_seal', s, null, message);
              r = setupR(cb, { kem: 0x647a, skR: bob.secret_key, info: 'pq demo' }, flipBit(enc.value, -1));
              return cb.call('hpke_open', r, null, ct);
            } finally {
              cb.call('hpke_context_free', s);
              if (r) cb.call('hpke_context_free', r);
            }
          }),
        ];
      },
    },
  ],
};
