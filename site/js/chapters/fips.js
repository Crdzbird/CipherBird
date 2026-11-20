import { row, refuses, mustRefuse } from '../kit.js';
import { hex, same, utf8, flipBit, fromHex } from '../bytes.js';
import { plain } from '../media.js';

/** Whether this engine has the fips profile, and whether its provider is loaded. */
function gate(cb) {
  const available = cb.call('fips_available') === 1;
  const status = cb.call('fips_status');
  return { available, status, ready: available && status.loaded === 1 };
}

/** A text row with the outcome of a call that may be refused. */
function outcome(label, fn) {
  const r = refuses(fn);
  if (r.refused) return { row: row.text(label, `refused: ${plain(r.message)}`), refused: true };
  const v = r.value;
  return { row: v instanceof Uint8Array ? row.bytes(label, v) : row.text(label, plain(JSON.stringify(v))), refused: false, value: v };
}

/** Rows for calls that must all refuse in a build without the provider, plus one check that they did. */
function refusedAll(label, attempts) {
  const rows = attempts.map(([name, fn]) => outcome(name, fn));
  const all = rows.every((r) => r.refused);
  return [...rows.map((r) => r.row), row.check(label, all, all ? `${rows.length} of ${rows.length} refused` : 'one was accepted')];
}

const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const RFC5869_OKM = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';
const notHere = 'This engine is not the fips profile, so the call reports that and does nothing. No fips_* function falls back to code outside the validated module.';

export default {
  id: 'fips',
  title: 'FIPS profile',
  lead: 'The fips build routes every operation through the OpenSSL FIPS Provider (CMVP certificate #4985, OpenSSL 3.1.2) and compiles nothing libsodium-backed. This page asks the engine in your browser what it is, and shows what it does when it is not that build.',
  demos: [
    {
      id: 'status',
      title: 'Is the validated module here?',
      statement: 'fips_available says whether this library was built in the fips profile, and fips_status whether the provider is loaded, self-tested and enforcing approved mode. A status must never claim approved mode without a loaded, tested module.',
      inputs: [],
      run(cb) {
        const before = gate(cb);
        const init = outcome('fips_init with the default module location', () => cb.call('fips_init', null, null));
        const { status } = gate(cb);
        const yesNo = (v) => (v ? 'yes' : 'no');
        return [
          row.text('Built in the fips profile', yesNo(before.available)),
          row.table('fips_status', ['Field', 'Value'], [
            ['loaded', yesNo(status.loaded)],
            ['self_tests_passed', yesNo(status.self_tests_passed)],
            ['approved_mode', yesNo(status.approved_mode)],
            ['provider_name', plain(status.provider_name ?? 'none')],
            ['provider_version', plain(status.provider_version ?? 'none')],
            ['module_directory', plain(status.module_directory ?? 'none')],
            ['config_file', plain(status.config_file ?? 'none')],
          ]),
          init.row,
          row.check('Approved mode only with a loaded, self-tested module',
            !status.approved_mode || (status.loaded && status.self_tests_passed), status.approved_mode ? 'approved and tested' : 'not claimed'),
          row.check('A build without the profile reports nothing loaded', before.available || (!status.loaded && !status.approved_mode),
            before.available ? 'fips build' : 'nothing loaded'),
          row.text('What the profile is for', 'Deployments whose regulator requires validated cryptography: servers load fips.so or fips.dylib with its fipsmodule.cnf, run the power-up self tests, and fetch every algorithm with fips=yes.'),
          row.text('This engine', before.available
            ? 'the fips profile'
            : 'the full profile compiled to WebAssembly; a browser cannot load the provider module, so the fips_* calls on this page refuse and the counterparts below come from the full profile instead'),
        ];
      },
    },
    {
      id: 'digests',
      title: 'Approved hashes, MACs and key derivation',
      statement: 'SHA-2, SHA3-256, HMAC, HKDF and PBKDF2, each with a hash id: 0 SHA-256, 1 SHA-384, 2 SHA-512, 3 SHA3-256. Without the module every call refuses, and the full profile computes the same SHA-2 and HKDF answers outside it.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'abc' }],
      run(cb, { message }) {
        const { ready } = gate(cb);
        const key = cb.call('sha256', 'fips demo key');
        const salt = utf8.encode('sixteen byte salt');
        if (ready) {
          const tag = cb.call('fips_hmac', 0, key, message);
          return [
            row.bytes('SHA-256', cb.call('fips_digest', 0, message)),
            row.bytes('SHA-384', cb.call('fips_digest', 1, message)),
            row.bytes('SHA-512', cb.call('fips_digest', 2, message)),
            row.bytes('SHA3-256', cb.call('fips_digest', 3, message)),
            row.check('SHA-256 of "abc" matches FIPS 180-4', hex(cb.call('fips_digest', 0, 'abc')) === SHA256_ABC, 'known answer'),
            row.bytes('HMAC-SHA256', tag),
            row.check('The tag verifies', cb.call('fips_hmac_verify', 0, key, message, tag) === 1, 'valid'),
            mustRefuse('A flipped tag is refused', () => cb.call('fips_hmac_verify', 0, key, message, flipBit(tag))),
            row.bytes('HKDF-SHA256, 32 bytes', cb.call('fips_hkdf', 0, message, salt, 'demo', 32)),
            row.bytes('PBKDF2-SHA256, 10000 rounds', cb.call('fips_pbkdf2', 0, message, salt, 10000, 32)),
            row.bytes('16 bytes from the module CTR_DRBG', cb.call('fips_random', 16)),
          ];
        }
        const ikm = new Uint8Array(22).fill(0x0b);
        const rfcSalt = Uint8Array.from({ length: 13 }, (_, i) => i);
        const info = Uint8Array.from({ length: 10 }, (_, i) => 0xf0 + i);
        const okm = cb.call('hkdf_derive', ikm, rfcSalt, info, 42);
        return [
          row.text('Why these refuse', notHere),
          ...refusedAll('Every fips_* call here refuses', [
            ['fips_digest SHA-256', () => cb.call('fips_digest', 0, message)],
            ['fips_digest SHA3-256', () => cb.call('fips_digest', 3, message)],
            ['fips_hmac', () => cb.call('fips_hmac', 0, key, message)],
            ['fips_hmac_verify', () => cb.call('fips_hmac_verify', 0, key, message, new Uint8Array(32))],
            ['fips_hkdf', () => cb.call('fips_hkdf', 0, message, salt, 'demo', 32)],
            ['fips_pbkdf2', () => cb.call('fips_pbkdf2', 0, message, salt, 10000, 32)],
            ['fips_random', () => cb.call('fips_random', 16)],
          ]),
          row.bytes('Full profile: SHA-256', cb.call('sha256', message)),
          row.bytes('Full profile: SHA-512', cb.call('sha512', message)),
          row.bytes('Full profile: HMAC-SHA256', cb.call('hmac_sha256', message, key)),
          row.check('Full profile SHA-256 of "abc" matches FIPS 180-4', hex(cb.call('sha256', 'abc')) === SHA256_ABC, 'known answer'),
          row.check('Full profile HKDF-SHA256 matches RFC 5869 test case 1', same(okm, fromHex(RFC5869_OKM)), 'known answer'),
          row.text('The difference', 'Same algorithms and answers, but computed by the full profile, not inside a validated module boundary.'),
        ];
      },
    },
    {
      id: 'aes-gcm',
      title: 'AES-256-GCM with the IV made inside the module',
      statement: 'In the fips profile the module constructs the 12-byte IV itself, so a caller cannot reuse one, and the wire is iv, ciphertext, tag. Here the call refuses, and the full profile shows the same cipher.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'payroll batch 2026-11' }],
      run(cb, { message }) {
        const { ready } = gate(cb);
        const key = cb.call('random_bytes', 32);
        const aad = 'ledger/v1';
        const rows = [];
        if (ready) {
          const wire = cb.call('fips_aes_gcm_encrypt', key, message, aad);
          const back = cb.call('fips_aes_gcm_decrypt', key, wire, aad);
          rows.push(
            row.bytes('Wire: iv(12) | ciphertext | tag(16)', wire),
            row.check('It decrypts', same(back, utf8.encode(message)), utf8.decode(back)),
            mustRefuse('A flipped bit is refused', () => cb.call('fips_aes_gcm_decrypt', key, flipBit(wire), aad)),
            row.check('Two encryptions use two IVs', !same(wire.subarray(0, 12), cb.call('fips_aes_gcm_encrypt', key, message, aad).subarray(0, 12)), 'fresh IV'),
          );
        } else {
          rows.push(row.text('Why these refuse', notHere), ...refusedAll('Both fips GCM calls refuse', [
            ['fips_aes_gcm_encrypt', () => cb.call('fips_aes_gcm_encrypt', key, message, aad)],
            ['fips_aes_gcm_decrypt', () => cb.call('fips_aes_gcm_decrypt', key, new Uint8Array(40), aad)],
          ]));
        }
        if (cb.call('aes256gcm_available') === 1) {
          const ct = cb.call('aes256gcm_encrypt', message, key, aad);
          const back = cb.call('aes256gcm_decrypt', ct, key, aad);
          rows.push(
            row.bytes('Full profile AES-256-GCM: nonce | ciphertext | tag', ct),
            row.check('Full profile round trip', same(back, utf8.encode(message)), utf8.decode(back)),
            mustRefuse('Full profile refuses a flipped bit', () => cb.call('aes256gcm_decrypt', flipBit(ct), key, aad)),
          );
        } else {
          rows.push(row.text('Full profile AES-256-GCM', 'not available in this engine'));
        }
        return rows;
      },
    },
    {
      id: 'p256',
      title: 'P-256 signatures and key agreement',
      statement: 'The fips profile signs with ECDSA P-256 and SHA-256 (DER signatures) and agrees keys with ECDH inside the module. Without it, keygen hands back no key material and verify says no.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'approve invoice 5521' }],
      run(cb, { message }) {
        const { ready } = gate(cb);
        if (ready) {
          const alice = cb.call('fips_p256_keygen');
          const bob = cb.call('fips_p256_keygen');
          const sig = cb.call('fips_p256_sign', alice.secret_key, message);
          const ab = cb.call('fips_p256_ecdh', alice.secret_key, bob.public_key);
          const ba = cb.call('fips_p256_ecdh', bob.secret_key, alice.public_key);
          return [
            row.bytes('Public key (65 bytes, uncompressed)', alice.public_key),
            row.bytes('Signature (DER)', sig),
            row.check('The signature verifies', cb.call('fips_p256_verify', alice.public_key, message, sig) === 1, 'valid'),
            mustRefuse('An edited message is refused', () => cb.call('fips_p256_verify', alice.public_key, `${message}.`, sig)),
            row.check('Public key recomputed from the private key matches', same(cb.call('fips_p256_public_key', alice.secret_key), alice.public_key), 'same point'),
            row.check('Both sides of ECDH agree', same(ab, ba), hex(ab).slice(0, 16)),
          ];
        }
        const kp = cb.call('fips_p256_keygen');
        const verified = cb.call('fips_p256_verify', new Uint8Array(65), message, new Uint8Array(72));
        return [
          row.text('Why these refuse', notHere),
          row.check('fips_p256_keygen returns no key material', kp.public_key.length === 0 && kp.secret_key.length === 0,
            `${kp.public_key.length} and ${kp.secret_key.length} bytes`),
          row.check('fips_p256_verify says no', verified === 0, 'returned 0'),
          ...refusedAll('Sign, ECDH and public-key derivation refuse', [
            ['fips_p256_sign', () => cb.call('fips_p256_sign', new Uint8Array(32), message)],
            ['fips_p256_ecdh', () => cb.call('fips_p256_ecdh', new Uint8Array(32), new Uint8Array(65))],
            ['fips_p256_public_key', () => cb.call('fips_p256_public_key', new Uint8Array(32))],
          ]),
          row.text('Full profile P-256 in this engine', cb.call('p256_available') ? 'available as cipherbird_p256_* (raw r||s signatures)' : 'not in this engine either: p256_available is 0 because the web engine trims it from libcrypto'),
        ];
      },
    },
    {
      id: 'envelope',
      title: 'A key envelope with approved key wrapping',
      statement: 'The FKR1 envelope wraps one 32-byte master secret in up to 16 slots, each a PBKDF2 passphrase or an HKDF key factor under AES-256-GCM. Any slot unlocks the same secret.',
      inputs: [{ name: 'passphrase', label: 'Passphrase', kind: 'text', value: 'quarterly close 2026' }],
      run(cb, { passphrase }) {
        const { ready } = gate(cb);
        const factor = cb.call('random_bytes', 32);
        if (!ready) {
          return [
            row.text('Why these refuse', notHere),
            ...refusedAll('Every envelope call refuses', [
              ['fips_envelope_create', () => cb.call('fips_envelope_create')],
              ['fips_envelope_deserialise', () => cb.call('fips_envelope_deserialise', utf8.encode('FKR1'))],
              ['fips_envelope_add_passphrase_slot', () => cb.call('fips_envelope_add_passphrase_slot', 0, passphrase, 10000)],
              ['fips_envelope_add_key_slot', () => cb.call('fips_envelope_add_key_slot', 0, factor)],
              ['fips_envelope_unlock_with_passphrase', () => cb.call('fips_envelope_unlock_with_passphrase', 0, passphrase)],
              ['fips_envelope_unlock_with_key', () => cb.call('fips_envelope_unlock_with_key', 0, factor)],
              ['fips_envelope_remove_slot', () => cb.call('fips_envelope_remove_slot', 0, 0)],
              ['fips_envelope_serialise', () => cb.call('fips_envelope_serialise', 0)],
            ]),
            row.check('fips_envelope_slot_count reports no slots', cb.call('fips_envelope_slot_count', 0) === 0, '0'),
          ];
        }
        const env = cb.call('fips_envelope_create');
        let copy = 0;
        try {
          cb.call('fips_envelope_add_passphrase_slot', env, passphrase, 10000);
          cb.call('fips_envelope_add_key_slot', env, factor);
          const blob = cb.call('fips_envelope_serialise', env);
          copy = cb.call('fips_envelope_deserialise', blob);
          const viaPass = cb.call('fips_envelope_unlock_with_passphrase', copy, passphrase);
          const viaKey = cb.call('fips_envelope_unlock_with_key', copy, factor);
          const slots = cb.call('fips_envelope_slot_count', copy);
          cb.call('fips_envelope_remove_slot', copy, 0);
          return [
            row.bytes('Serialised envelope', blob),
            row.text('Slots', slots),
            row.check('Passphrase and key factor unlock the same secret', same(viaPass, viaKey) && viaPass.length === 32, '32 bytes'),
            mustRefuse('A wrong passphrase is refused', () => cb.call('fips_envelope_unlock_with_passphrase', copy, `${passphrase}!`)),
            row.check('Removing a slot leaves one', cb.call('fips_envelope_slot_count', copy) === slots - 1, String(slots - 1)),
          ];
        } finally {
          cb.call('fips_envelope_free', env);
          if (copy) cb.call('fips_envelope_free', copy);
        }
      },
    },
    {
      id: 'hpke',
      title: 'HPKE over P-256',
      statement: 'RFC 9180 base mode with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, one shot, inside the module. The sender gets a 65-byte enc to send with the ciphertext.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'merger code name: heron' }],
      run(cb, { message }) {
        const { ready } = gate(cb);
        const info = 'board/v1';
        const aad = 'minutes';
        if (ready) {
          const r = cb.call('fips_p256_keygen');
          const enc = cb.Out.buffer();
          const ct = cb.call('fips_hpke_p256_seal', r.public_key, info, aad, message, enc);
          const back = cb.call('fips_hpke_p256_open', enc.value, r.secret_key, r.public_key, info, aad, ct);
          return [
            row.bytes('enc (65 bytes)', enc.value),
            row.bytes('Ciphertext', ct),
            row.check('The recipient opens it', same(back, utf8.encode(message)), utf8.decode(back)),
            mustRefuse('Other associated data is refused', () => cb.call('fips_hpke_p256_open', enc.value, r.secret_key, r.public_key, info, `${aad}.`, ct)),
          ];
        }
        const enc = cb.Out.buffer();
        return [
          row.text('Why these refuse', notHere),
          ...refusedAll('Both HPKE calls refuse', [
            ['fips_hpke_p256_seal', () => cb.call('fips_hpke_p256_seal', new Uint8Array(65), info, aad, message, enc)],
            ['fips_hpke_p256_open', () => cb.call('fips_hpke_p256_open', new Uint8Array(65), new Uint8Array(32), new Uint8Array(65), info, aad, new Uint8Array(32))],
          ]),
          row.text('Full profile HPKE', 'The full profile offers HPKE with DHKEM(X25519), ML-KEM-768 and X-Wing through cipherbird_hpke_*; HPKE over P-256 is only in the fips profile.'),
        ];
      },
    },
  ],
};
