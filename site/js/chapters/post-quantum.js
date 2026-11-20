import { row, mustRefuse, refuses, timed } from '../kit.js';
import { hex, fromHex, same, flipBit } from '../bytes.js';

const ML_KEM = { 'ML-KEM-512': 0, 'ML-KEM-768': 1, 'ML-KEM-1024': 2 };
const ML_DSA = { 'ML-DSA-44': 0, 'ML-DSA-65': 1, 'ML-DSA-87': 2 };
const SLH_LEVEL = { '128s': 0, '128f': 1, '192s': 2, '192f': 3, '256s': 4, '256f': 5 };
const SLH_HASH = { SHA2: 0, SHAKE: 1 };

const XWING_SEED = '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26';
const XWING_PK_SHA256 = '2e816deebcd76c5c80d0cd2d174478871658e8e2ff42bc9d4a6e486372e856bb';

const ms = (t) => `${t.toFixed(1)} ms`;

function kems(cb) {
  const list = [['X25519 (classic)', () => {
    const a = cb.call('x25519_keygen');
    const b = cb.call('x25519_keygen');
    return { kp: a, ct: b.public_key, ss: cb.call('x25519_shared_secret', b.secret_key, a.public_key),
      back: cb.call('x25519_shared_secret', a.secret_key, b.public_key) };
  }]];
  for (const [name, level] of Object.entries(ML_KEM)) {
    list.push([name, () => {
      const kp = cb.call('ml_kem_keygen', level);
      const e = cb.call('ml_kem_encapsulate', kp.public_key, level);
      return { kp, ct: e.ciphertext, ss: e.shared_secret, back: cb.call('ml_kem_decapsulate', e.ciphertext, kp.secret_key, level) };
    }]);
  }
  for (const [name, prefix] of [['X25519 + ML-KEM-768', 'hybrid_kem'], ['X25519 + sntrup761', 'sntrup_x25519'], ['X-Wing', 'xwing']]) {
    list.push([name, () => {
      const kp = cb.call(`${prefix}_keygen`);
      const e = cb.call(`${prefix}_encapsulate`, kp.public_key);
      return { kp, ct: e.ciphertext, ss: e.shared_secret, back: cb.call(`${prefix}_decapsulate`, e.ciphertext, kp.secret_key) };
    }]);
  }
  return list;
}

function signers(cb) {
  const list = [['Ed25519 (classic)', (m) => {
    const kp = cb.call('ed25519_keygen');
    const sig = cb.call('ed25519_sign', m, kp.secret_key);
    return { kp, sig, ok: cb.call('ed25519_verify', m, sig, kp.public_key) === 1 };
  }]];
  for (const [name, level] of Object.entries(ML_DSA)) {
    list.push([name, (m) => {
      const kp = cb.call('ml_dsa_keygen', level);
      const sig = cb.call('ml_dsa_sign', m, kp.secret_key, level);
      return { kp, sig, ok: cb.call('ml_dsa_verify', m, sig, kp.public_key, level) === 1 };
    }]);
  }
  list.push(['SLH-DSA-SHA2-128f', (m) => {
    const kp = cb.call('slh_dsa_keygen', SLH_LEVEL['128f'], SLH_HASH.SHA2);
    const sig = cb.call('slh_dsa_sign', m, kp.secret_key, SLH_LEVEL['128f'], SLH_HASH.SHA2);
    return { kp, sig, ok: cb.call('slh_dsa_verify', m, sig, kp.public_key, SLH_LEVEL['128f'], SLH_HASH.SHA2) === 1 };
  }]);
  list.push(['Ed25519 + ML-DSA-65', (m) => {
    const kp = cb.call('hybrid_sig_keygen');
    const sig = cb.call('hybrid_sig_sign', m, kp.secret_key);
    return { kp, sig, ok: cb.call('hybrid_sig_verify', m, sig, kp.public_key) === 1 };
  }]);
  return list;
}

function wrongKeyOutcome(fn, real) {
  const outcome = refuses(fn);
  if (outcome.refused) return { ok: true, text: `refused: ${outcome.message}` };
  return { ok: !same(outcome.value, real), text: same(outcome.value, real) ? 'same secret' : 'an unrelated secret, no error' };
}

export default {
  id: 'post-quantum',
  title: 'Post-quantum cryptography',
  lead: 'The NIST post-quantum standards ML-KEM, ML-DSA and SLH-DSA, the X-Wing combiner, and hybrids that pair each with a classic algorithm. All of it runs in the engine, here in the page.',
  demos: [
    {
      id: 'sizes',
      title: 'What post-quantum costs in bytes',
      statement: 'Post-quantum keys, ciphertexts and signatures are tens to hundreds of times larger than the classic ones. Every length below is measured on keys made just now.',
      inputs: [],
      run(cb) {
        const kemRows = [];
        let agreed = true;
        for (const [name, make] of kems(cb)) {
          const r = make();
          agreed = agreed && same(r.ss, r.back) && r.ss.length === 32;
          kemRows.push([name, r.kp.public_key.length, r.kp.secret_key.length, r.ct.length, r.ss.length]);
        }
        const sigRows = [];
        let verified = true;
        for (const [name, make] of signers(cb)) {
          const r = make('size check');
          verified = verified && r.ok;
          sigRows.push([name, r.kp.public_key.length, r.kp.secret_key.length, r.sig.length]);
        }
        return [
          row.table('Key exchange (bytes)', ['Algorithm', 'Public key', 'Secret key', 'Ciphertext', 'Shared secret'], kemRows,
            'For X25519 the ciphertext is the other side public key.'),
          row.table('Signatures (bytes)', ['Algorithm', 'Public key', 'Secret key', 'Signature'], sigRows),
          row.check('Every key exchange agrees on a 32-byte secret', agreed, `${kemRows.length} algorithms`),
          row.check('Every signature verifies', verified, `${sigRows.length} algorithms`),
          row.check('ML-KEM-768 public key is 37 times the X25519 one', kemRows[2][1] === 1184 && kemRows[0][1] === 32, `${kemRows[2][1]} vs ${kemRows[0][1]} bytes`),
        ];
      },
    },
    {
      id: 'ml-kem',
      title: 'ML-KEM and implicit rejection',
      statement: 'ML-KEM (FIPS 203) sends a fresh 32-byte secret to a public key. A wrong key or a damaged ciphertext gives no error, just an unrelated secret, so the failure leaks nothing.',
      inputs: [{ name: 'set', label: 'Parameter set', kind: 'select', value: 'ML-KEM-768', options: Object.keys(ML_KEM) }],
      run(cb, { set }) {
        const level = ML_KEM[set];
        const kg = timed(() => cb.call('ml_kem_keygen', level));
        const kp = kg.value;
        const other = cb.call('ml_kem_keygen', level);
        const enc = timed(() => cb.call('ml_kem_encapsulate', kp.public_key, level));
        const { ciphertext, shared_secret: sent } = enc.value;
        const dec = timed(() => cb.call('ml_kem_decapsulate', ciphertext, kp.secret_key, level));
        const wrongKey = cb.call('ml_kem_decapsulate', ciphertext, other.secret_key, level);
        const damaged = cb.call('ml_kem_decapsulate', flipBit(ciphertext, 100), kp.secret_key, level);
        return [
          row.bytes('Ciphertext', ciphertext),
          row.bytes('Shared secret (sender)', sent),
          row.bytes('Shared secret (recipient)', dec.value),
          row.text('Time', `keygen ${ms(kg.ms)}, encapsulate ${ms(enc.ms)}, decapsulate ${ms(dec.ms)}`),
          row.check('Sender and recipient agree', same(sent, dec.value), 'identical'),
          row.bytes('Decapsulated with another secret key', wrongKey),
          row.check('The wrong secret key gives no error and an unrelated secret', wrongKey.length === 32 && !same(wrongKey, sent), 'implicit rejection'),
          row.check('A ciphertext with one flipped bit also gives an unrelated secret', damaged.length === 32 && !same(damaged, sent), 'implicit rejection'),
          mustRefuse('A public key of the wrong length is refused', () => cb.call('ml_kem_encapsulate', kp.public_key.subarray(1), level)),
        ];
      },
    },
    {
      id: 'hybrid-kems',
      title: 'Hybrid key exchange: two locks on one door',
      statement: 'A hybrid KEM runs X25519 and a post-quantum KEM together and combines both secrets. It stays safe while either one is unbroken.',
      inputs: [],
      run(cb) {
        const mlkemPk = cb.call('ml_kem_keygen', 1).public_key.length;
        const rows = [];
        const out = [];
        for (const [name, prefix, pq] of [['X25519 + ML-KEM-768', 'hybrid_kem', mlkemPk], ['X25519 + sntrup761', 'sntrup_x25519', null]]) {
          const kp = cb.call(`${prefix}_keygen`);
          const other = cb.call(`${prefix}_keygen`);
          const t = timed(() => cb.call(`${prefix}_encapsulate`, kp.public_key));
          const back = cb.call(`${prefix}_decapsulate`, t.value.ciphertext, kp.secret_key);
          const wrong = wrongKeyOutcome(() => cb.call(`${prefix}_decapsulate`, t.value.ciphertext, other.secret_key), t.value.shared_secret);
          rows.push([name, kp.public_key.length, t.value.ciphertext.length, ms(t.ms)]);
          out.push(row.check(`${name}: both sides agree`, same(back, t.value.shared_secret), 'identical'));
          out.push(row.check(`${name}: another secret key does not recover the secret`, wrong.ok, wrong.text));
          if (pq) {
            out.push(row.check(`${name}: the public key is 32 bytes of X25519 then the ML-KEM-768 key`,
              kp.public_key.length === 32 + pq, `32 + ${pq} = ${kp.public_key.length}`));
          }
        }
        return [
          row.table('Hybrids', ['Hybrid', 'Public key', 'Ciphertext', 'Encapsulate'], rows),
          ...out,
          row.text('Why two lattices', 'sntrup761 is NTRU Prime, a different lattice family from ML-KEM, so an attack on one structure need not apply to the other.'),
        ];
      },
    },
    {
      id: 'xwing',
      title: 'X-Wing from a seed',
      statement: 'X-Wing combines ML-KEM-768 and X25519 with the combiner of the X-Wing draft, and its whole secret key is a 32-byte seed. The same seed always rebuilds the same 1216-byte public key.',
      inputs: [{ name: 'phrase', label: 'Phrase hashed into a seed', kind: 'text', value: 'X-Wing demo seed' }],
      run(cb, { phrase }) {
        const seed = cb.call('sha256', phrase);
        const a = cb.call('xwing_keypair_from_seed', seed);
        const b = cb.call('xwing_keypair_from_seed', seed);
        const vector = cb.call('xwing_keypair_from_seed', fromHex(XWING_SEED));
        const fresh = cb.call('xwing_keygen');
        const enc = cb.call('xwing_encapsulate', a.public_key);
        const back = cb.call('xwing_decapsulate', enc.ciphertext, a.secret_key);
        const wrong = wrongKeyOutcome(() => cb.call('xwing_decapsulate', enc.ciphertext, fresh.secret_key), enc.shared_secret);
        return [
          row.bytes('Seed = SHA-256 of the phrase', seed),
          row.bytes('Public key', a.public_key),
          row.text('Sizes', `public key ${a.public_key.length} B, secret key ${a.secret_key.length} B, ciphertext ${enc.ciphertext.length} B`),
          row.check('The same seed gives the same key pair', same(a.public_key, b.public_key) && same(a.secret_key, b.secret_key), 'identical'),
          row.check('The secret key is the seed itself', same(a.secret_key, seed), '32 bytes'),
          row.check('draft-connolly-cfrg-xwing-kem-11 vector 1: SHA-256 of the public key matches',
            hex(cb.call('sha256', vector.public_key)) === XWING_PK_SHA256, 'known answer'),
          row.check('Encapsulate then decapsulate agree', same(back, enc.shared_secret), 'identical'),
          row.check('A random key pair cannot recover the secret', wrong.ok, wrong.text),
          row.check('A 31-byte seed gives no key pair at all', cb.call('xwing_keypair_from_seed', seed.subarray(0, 31)).public_key.length === 0,
            'empty keys'),
        ];
      },
    },
    {
      id: 'ml-dsa',
      title: 'ML-DSA signatures',
      statement: 'ML-DSA (FIPS 204) is the general-purpose post-quantum signature. It is fast to sign and verify; the price is size.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'firmware image 7, build 2210' },
        { name: 'set', label: 'Parameter set', kind: 'select', value: 'ML-DSA-65', options: Object.keys(ML_DSA) },
      ],
      run(cb, { message, set }) {
        const level = ML_DSA[set];
        const kg = timed(() => cb.call('ml_dsa_keygen', level));
        const kp = kg.value;
        const other = cb.call('ml_dsa_keygen', level);
        const sg = timed(() => cb.call('ml_dsa_sign', message, kp.secret_key, level));
        const sig = sg.value;
        const vf = timed(() => cb.call('ml_dsa_verify', message, sig, kp.public_key, level));
        return [
          row.bytes('Signature', sig),
          row.text('Sizes', `public key ${kp.public_key.length} B, secret key ${kp.secret_key.length} B, signature ${sig.length} B`),
          row.text('Time', `keygen ${ms(kg.ms)}, sign ${ms(sg.ms)}, verify ${ms(vf.ms)}`),
          row.check('The signature verifies', vf.value === 1, 'valid'),
          mustRefuse('An edited message is refused', () => cb.call('ml_dsa_verify', `${message}?`, sig, kp.public_key, level)),
          mustRefuse('A flipped bit in the signature is refused', () => cb.call('ml_dsa_verify', message, flipBit(sig, 500), kp.public_key, level)),
          mustRefuse('Another public key does not accept it', () => cb.call('ml_dsa_verify', message, sig, other.public_key, level)),
        ];
      },
    },
    {
      id: 'slh-dsa',
      title: 'SLH-DSA: signatures from hashes alone',
      statement: 'SLH-DSA (FIPS 205) rests only on the security of a hash function, a very conservative assumption. The s sets give smaller signatures but sign far more slowly than the f sets.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'root certificate, valid until 2050' },
        { name: 'level', label: 'Security and speed', kind: 'select', value: '128f', options: Object.keys(SLH_LEVEL) },
        { name: 'hash', label: 'Hash family', kind: 'select', value: 'SHA2', options: Object.keys(SLH_HASH) },
      ],
      run(cb, { message, level, hash }) {
        const l = SLH_LEVEL[level];
        const h = SLH_HASH[hash];
        const kg = timed(() => cb.call('slh_dsa_keygen', l, h));
        const kp = kg.value;
        const sg = timed(() => cb.call('slh_dsa_sign', message, kp.secret_key, l, h));
        const sig = sg.value;
        const vf = timed(() => cb.call('slh_dsa_verify', message, sig, kp.public_key, l, h));
        return [
          row.text('Parameter set', `SLH-DSA-${hash}-${level}`),
          row.text('Sizes', `public key ${kp.public_key.length} B, secret key ${kp.secret_key.length} B, signature ${sig.length} B`),
          row.text('Time', `keygen ${ms(kg.ms)}, sign ${ms(sg.ms)}, verify ${ms(vf.ms)}`),
          row.bytes('Signature (first 64 bytes)', sig.subarray(0, 64), `of ${sig.length}`),
          row.check('The signature verifies', vf.value === 1, 'valid'),
          mustRefuse('An edited message is refused', () => cb.call('slh_dsa_verify', `${message}.`, sig, kp.public_key, l, h)),
          mustRefuse('A flipped bit in the signature is refused', () => cb.call('slh_dsa_verify', message, flipBit(sig, 1000), kp.public_key, l, h)),
          mustRefuse('The same signature checked under the other hash family is refused',
            () => cb.call('slh_dsa_verify', message, sig, kp.public_key, l, 1 - h)),
        ];
      },
    },
    {
      id: 'hybrid-sig',
      title: 'Hybrid signature: both halves must hold',
      statement: 'The hybrid signature is an Ed25519 signature followed by an ML-DSA-65 one, over the same message. It verifies only when both do, so breaking one algorithm is not enough.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'transfer 1,000 to the escrow account' }],
      run(cb, { message }) {
        const kp = cb.call('hybrid_sig_keygen');
        const sig = cb.call('hybrid_sig_sign', message, kp.secret_key);
        const ed = sig.subarray(0, 64);
        const pq = sig.subarray(64);
        return [
          row.text('Layout', `signature ${sig.length} B = Ed25519 64 + ML-DSA-65 ${pq.length}; public key ${kp.public_key.length} B = 32 + ${kp.public_key.length - 32}`),
          row.bytes('Ed25519 half', ed),
          row.check('The hybrid signature verifies', cb.call('hybrid_sig_verify', message, sig, kp.public_key) === 1, 'valid'),
          row.check('The first 64 bytes are an ordinary Ed25519 signature',
            cb.call('ed25519_verify', message, ed, kp.public_key.subarray(0, 32)) === 1
            && same(ed, cb.call('ed25519_sign', message, kp.secret_key.subarray(0, 64))), 'verifies alone'),
          row.check('The rest is an ordinary ML-DSA-65 signature',
            cb.call('ml_dsa_verify', message, pq, kp.public_key.subarray(32), ML_DSA['ML-DSA-65']) === 1, 'verifies alone'),
          mustRefuse('Break the Ed25519 half: refused', () => cb.call('hybrid_sig_verify', message, flipBit(sig, 5), kp.public_key)),
          mustRefuse('Break the ML-DSA half: refused', () => cb.call('hybrid_sig_verify', message, flipBit(sig, 64 + 200), kp.public_key)),
          mustRefuse('Drop the ML-DSA half: refused', () => cb.call('hybrid_sig_verify', message, ed, kp.public_key)),
        ];
      },
    },
  ],
};
