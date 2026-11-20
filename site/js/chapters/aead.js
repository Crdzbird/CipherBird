import { row, mustRefuse, timed } from '../kit.js';
import { same, utf8, flipBit, concat } from '../bytes.js';

const TAG_MESSAGE = 0;
const TAG_FINAL = 3;

function readU64(bytes, at) {
  return Number(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(at, true));
}

function openStream(cb, key, header, chunks) {
  const d = cb.call('stream_dec_create', key, header);
  try {
    const parts = [];
    let last = -1;
    for (const chunk of chunks) {
      const tag = cb.Out.scalar();
      parts.push(cb.call('stream_dec_pull', d, chunk, tag));
      last = tag.value;
    }
    return { plaintext: concat(...parts), last };
  } finally {
    cb.call('stream_dec_free', d);
  }
}

export default {
  id: 'aead',
  title: 'Authenticated encryption',
  lead: 'XChaCha20-Poly1305, AES-256-GCM, a key-committing AEAD, chunked SecretStream and the layered MolecularVault. Every one of them refuses a ciphertext that was changed by a single bit.',
  demos: [
    {
      id: 'xchacha',
      title: 'Encrypt and authenticate a message',
      statement: 'XChaCha20-Poly1305 with a fresh 24-byte random nonce per message. The associated data is not encrypted but is authenticated, so a ciphertext moved to another context is refused.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'invoice 1042: pay 1,250.00 EUR to account 7' },
        { name: 'aad', label: 'Associated data', kind: 'text', value: 'customer=acme;invoice=1042' },
      ],
      run(cb, { message, aad }) {
        const key = cb.call('sym_keygen');
        const ct = cb.call('xchacha20_encrypt', message, key, aad);
        const again = cb.call('xchacha20_encrypt', message, key, aad);
        const pt = cb.call('xchacha20_decrypt', ct, key, aad);
        return [
          row.bytes('Key (sym_keygen, 32 bytes)', key),
          row.bytes('Nonce', ct.subarray(0, 24), 'first 24 bytes'),
          row.bytes('Ciphertext and tag', ct.subarray(24), `${ct.length - 24 - 16} bytes of ciphertext, 16-byte tag`),
          row.text('Decrypted', utf8.decode(pt)),
          row.check('Round trip gives back the message', same(pt, utf8.encode(message)), 'identical'),
          row.check('Same message twice, two different ciphertexts', !same(ct, again), 'fresh nonce'),
          mustRefuse('Other associated data is refused', () => cb.call('xchacha20_decrypt', ct, key, `${aad};x`)),
          mustRefuse('One flipped bit is refused', () => cb.call('xchacha20_decrypt', flipBit(ct, 30), key, aad)),
          mustRefuse('Another key is refused', () => cb.call('xchacha20_decrypt', ct, cb.call('sym_keygen'), aad)),
        ];
      },
    },
    {
      id: 'aes-gcm',
      title: 'AES-256-GCM where the build has it',
      statement: 'libsodium runs AES-GCM only on CPUs with AES instructions; builds that carry OpenSSL fall back to its portable code. Ask aes256gcm_available first and use XChaCha20 when it says no.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'quarterly report, draft 3' }],
      run(cb, { message }) {
        const available = cb.call('aes256gcm_available') === 1;
        const rows = [row.text('aes256gcm_available', available ? '1: available in this engine' : '0: not available in this engine')];
        if (!available) {
          rows.push(row.text('What to use instead', 'XChaCha20-Poly1305, shown above, which runs everywhere'));
          return rows;
        }
        const key = cb.call('sym_keygen');
        const ct = cb.call('aes256gcm_encrypt', message, key, 'report');
        const pt = cb.call('aes256gcm_decrypt', ct, key, 'report');
        rows.push(
          row.bytes('Nonce', ct.subarray(0, 12), '12 bytes, random per message'),
          row.bytes('Ciphertext and tag', ct.subarray(12)),
          row.check('Layout is nonce, ciphertext, 16-byte tag', ct.length === 12 + utf8.encode(message).length + 16, `${ct.length} bytes`),
          row.check('Round trip gives back the message', same(pt, utf8.encode(message)), utf8.decode(pt)),
          mustRefuse('One flipped bit is refused', () => cb.call('aes256gcm_decrypt', flipBit(ct), key, 'report')),
          mustRefuse('Other associated data is refused', () => cb.call('aes256gcm_decrypt', ct, key, 'memo')),
          row.text('Nonce budget', 'rotate the key well before 2^32 messages; the 96-bit nonce is random'),
        );
        return rows;
      },
    },
    {
      id: 'committing',
      title: 'A ciphertext that commits to its key',
      statement: 'Plain AEADs do not bind a ciphertext to one key. This one prepends a 32-byte commitment to the key and the associated data, derived with HKDF-SHA256, and checks it before decrypting.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'the vault code is 4471' },
        { name: 'aad', label: 'Associated data', kind: 'text', value: 'room=12' },
      ],
      run(cb, { message, aad }) {
        const key = cb.call('sym_keygen');
        const ct = cb.call('committing_encrypt', message, key, aad);
        const again = cb.call('committing_encrypt', message, key, aad);
        const okm = cb.call('hkdf_expand', cb.call('hkdf_extract', 'cryptolib/cmt-aead/v1', key), aad, 64);
        const inner = cb.call('xchacha20_decrypt', ct.subarray(32), okm.subarray(0, 32), aad);
        return [
          row.bytes('Commitment', ct.subarray(0, 32), 'first 32 bytes'),
          row.bytes('XChaCha20-Poly1305 body', ct.subarray(32)),
          row.check('Commitment recomputed here with HKDF-SHA256', same(ct.subarray(0, 32), okm.subarray(32)),
            'second half of HKDF(key, "cryptolib/cmt-aead/v1", aad)'),
          row.check('Same key and context, same commitment, new nonce',
            same(ct.subarray(0, 32), again.subarray(0, 32)) && !same(ct, again), 'deterministic commitment'),
          row.check('The body is plain XChaCha20 under the first half', same(inner, utf8.encode(message)), utf8.decode(inner)),
          row.check('Decrypts under its own key', same(cb.call('committing_decrypt', ct, key, aad), utf8.encode(message)), 'valid'),
          mustRefuse('Another key is refused at the commitment', () => cb.call('committing_decrypt', ct, cb.call('sym_keygen'), aad)),
          mustRefuse('Other associated data is refused', () => cb.call('committing_decrypt', ct, key, `${aad}0`)),
          mustRefuse('A flipped commitment bit is refused', () => cb.call('committing_decrypt', flipBit(ct, 0), key, aad)),
        ];
      },
    },
    {
      id: 'secretstream',
      title: 'Encrypt a stream in chunks',
      statement: 'SecretStream encrypts a file piece by piece and marks the last piece FINAL. Chunks cannot be reordered, dropped or replayed, and a stream cut short never shows its final tag.',
      inputs: [
        { name: 'text', label: 'Text', kind: 'textarea', value: 'Chunk by chunk the backup leaves the phone, and the server can store it without ever reading a byte of it.' },
        { name: 'chunk', label: 'Chunk size (bytes)', kind: 'number', value: 24, min: 1, max: 256 },
      ],
      run(cb, { text, chunk }) {
        const data = utf8.encode(text);
        const step = Math.max(1, Number(chunk));
        const key = cb.call('sym_keygen');
        const enc = cb.call('stream_enc_create', key);
        let header;
        const chunks = [];
        try {
          header = cb.call('stream_enc_header', enc);
          for (let i = 0; i < data.length || i === 0; i += step) {
            const last = i + step >= data.length;
            chunks.push(cb.call('stream_enc_push', enc, data.subarray(i, i + step), last ? TAG_FINAL : TAG_MESSAGE));
            if (last) break;
          }
        } finally {
          cb.call('stream_enc_free', enc);
        }
        const whole = openStream(cb, key, header, chunks);
        const rows = [
          row.bytes('Stream header', header, '24 bytes, sent before the first chunk'),
          row.text('Chunks', `${chunks.length}, each 17 bytes larger than its plaintext`),
          row.bytes('First encrypted chunk', chunks[0]),
          row.check('Decrypted in order, every byte back', same(whole.plaintext, data), `${data.length} bytes`),
          row.check('Last chunk carries the FINAL tag', whole.last === TAG_FINAL, `tag ${whole.last}`),
          mustRefuse('A replayed chunk after FINAL is refused', () => openStream(cb, key, header, [...chunks, chunks[chunks.length - 1]])),
          mustRefuse('Another key is refused', () => openStream(cb, cb.call('sym_keygen'), header, chunks)),
          mustRefuse('One flipped bit in a chunk is refused',
            () => openStream(cb, key, header, [flipBit(chunks[0], 4), ...chunks.slice(1)])),
        ];
        if (chunks.length > 1) {
          const cut = openStream(cb, key, header, chunks.slice(0, -1));
          rows.push(
            mustRefuse('Two chunks swapped are refused', () => openStream(cb, key, header, [chunks[1], chunks[0], ...chunks.slice(2)])),
            mustRefuse('A dropped chunk is refused', () => openStream(cb, key, header, chunks.slice(1))),
            row.check('A truncated stream never reaches FINAL', cut.last !== TAG_FINAL,
              `${chunks.length - 1} chunks read, last tag ${cut.last}`),
          );
        }
        return rows;
      },
    },
    {
      id: 'molecular-passphrase',
      title: 'Three ciphers under one passphrase',
      statement: 'MolecularVault cascades XChaCha20-Poly1305 and AES-256-GCM-SIV under a key-committing outer layer, keyed by Argon2id. The envelope records its own salt and cost, so only the passphrase stays secret.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'recovery phrase: orbit lantern velvet seven' },
        { name: 'passphrase', label: 'Passphrase', kind: 'text', value: 'correct horse battery staple' },
        { name: 'memory', label: 'Argon2id memory (MiB)', kind: 'select', value: '16', options: ['8', '16', '32'] },
      ],
      run(cb, { message, passphrase, memory }) {
        const mem = Number(memory) * 1024 * 1024;
        const aad = 'backup:v1';
        const sealed = timed(() => cb.call('molecular_seal', message, passphrase, aad, 2, mem));
        const env = sealed.value;
        const opened = cb.call('molecular_open', env, passphrase, aad);
        return [
          row.text('Magic and version', `${utf8.decode(env.subarray(0, 4))} v${env[4]}, mode ${env[5]}`),
          row.text('Argon2id cost read from the header', `ops ${readU64(env, 6)}, memory ${readU64(env, 14) / 1048576} MiB`),
          row.bytes('Salt', env.subarray(22, 38)),
          row.bytes('Envelope', env, `${env.length} bytes for a ${utf8.encode(message).length}-byte message`),
          row.text('Time to seal', `${sealed.ms.toFixed(0)} ms`),
          row.check('The passphrase opens it', same(opened, utf8.encode(message)), utf8.decode(opened)),
          mustRefuse('A wrong passphrase is refused', () => cb.call('molecular_open', env, `${passphrase}.`, aad)),
          mustRefuse('Other associated data is refused', () => cb.call('molecular_open', env, passphrase, 'backup:v2')),
          mustRefuse('One flipped bit in the body is refused', () => cb.call('molecular_open', flipBit(env), passphrase, aad)),
          mustRefuse('A cost below the Argon2id minimum is refused', () => cb.call('molecular_seal', message, passphrase, aad, 1, 1024)),
        ];
      },
    },
    {
      id: 'molecular-key',
      title: 'MolecularVault under a raw key',
      statement: 'With a full-entropy 32-byte key, for example one agreed by a KEM, Argon2id is skipped and the header records cost zero. A key envelope cannot be opened as a passphrase envelope, or the other way round.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'wire 40,000.00 USD on 2026-12-01' }],
      run(cb, { message }) {
        const key = cb.call('sym_keygen');
        const env = cb.call('molecular_seal_with_key', message, key, 'treasury');
        const opened = cb.call('molecular_open_with_key', env, key, 'treasury');
        const passEnv = cb.call('molecular_seal', message, 'a passphrase', 'treasury', 1, 8 * 1024 * 1024);
        return [
          row.bytes('Envelope', env, `${env.length} bytes`),
          row.check('Header records no Argon2id cost', readU64(env, 6) === 0 && readU64(env, 14) === 0, 'ops 0, memory 0'),
          row.check('The key opens it', same(opened, utf8.encode(message)), utf8.decode(opened)),
          mustRefuse('Another key is refused', () => cb.call('molecular_open_with_key', env, cb.call('sym_keygen'), 'treasury')),
          mustRefuse('Other associated data is refused', () => cb.call('molecular_open_with_key', env, key, 'payroll')),
          mustRefuse('A key envelope is refused by the passphrase path', () => cb.call('molecular_open', env, 'a passphrase', 'treasury')),
          mustRefuse('A passphrase envelope is refused by the key path', () => cb.call('molecular_open_with_key', passEnv, key, 'treasury')),
        ];
      },
    },
  ],
};
