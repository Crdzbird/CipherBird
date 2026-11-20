import { row, bitDistance, mustRefuse, timed } from '../kit.js';
import { hex, same, utf8, concat } from '../bytes.js';

export default {
  id: 'hashing',
  title: 'Hashing and key derivation',
  lead: 'Eight hash functions, two MACs, HKDF and Argon2id. Every digest on this page is computed by the engine itself, not by the browser.',
  demos: [
    {
      id: 'digests',
      title: 'One message, eight digests',
      statement: 'SHA-2, BLAKE2b, BLAKE3, Keccak-256 and RIPEMD-160 side by side. Bitcoin and Ethereum addresses start from the last two.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'meet at the north gate' }],
      run(cb, { message }) {
        const sha = cb.call('sha256', message);
        return [
          row.bytes('SHA-256', sha),
          row.bytes('SHA-512', cb.call('sha512', message)),
          row.bytes('BLAKE2b-512', cb.call('blake2b', message, null)),
          row.bytes('BLAKE2b-256 (native length)', cb.call('blake2b_keyed', message, null, 32)),
          row.bytes('BLAKE3', cb.call('blake3', message, 0)),
          row.bytes('Keccak-256 (Ethereum)', cb.call('keccak256', message)),
          row.bytes('RIPEMD-160', cb.call('ripemd160', message)),
          row.bytes('HASH160 = RIPEMD-160 of SHA-256 (Bitcoin)', cb.call('ripemd160', sha)),
          row.check('SHA-256 of "abc" matches FIPS 180-4',
            hex(cb.call('sha256', 'abc')) === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
            'known answer'),
        ];
      },
    },
    {
      id: 'avalanche',
      title: 'Change one letter, lose half the bits',
      statement: 'A good hash has no near misses. Editing a single character flips about half of the output bits, so a digest leaks nothing about how close two inputs are.',
      inputs: [
        { name: 'a', label: 'First message', kind: 'text', value: 'pay Alice 100' },
        { name: 'b', label: 'Second message', kind: 'text', value: 'pay Alice 900' },
      ],
      run(cb, { a, b }) {
        const x = cb.call('blake3', a, 0);
        const y = cb.call('blake3', b, 0);
        const flipped = bitDistance(x, y);
        return [
          row.bytes('BLAKE3 of the first', x),
          row.bytes('BLAKE3 of the second', y),
          row.text('Bits that differ', `${flipped} of 256 (${((flipped / 256) * 100).toFixed(1)}%)`),
          row.check('Different inputs give unrelated digests', a === b || (flipped > 80 && flipped < 176),
            a === b ? 'identical inputs' : `${flipped} bits apart`),
        ];
      },
    },
    {
      id: 'blake3-stream',
      title: 'Hash a stream in pieces',
      statement: 'The incremental BLAKE3 hasher takes data as it arrives. Feeding it in chunks gives exactly the one-shot digest, and its output can be stretched to any length.',
      inputs: [
        { name: 'text', label: 'Text', kind: 'textarea', value: 'A file too large to hold in memory arrives in pieces, and the hash is ready the moment the last piece lands.' },
        { name: 'chunk', label: 'Chunk size (bytes)', kind: 'number', value: 7, min: 1, max: 64 },
        { name: 'length', label: 'Output length (bytes)', kind: 'number', value: 64, min: 1, max: 128 },
      ],
      run(cb, { text, chunk, length }) {
        const data = utf8.encode(text);
        const step = Math.max(1, Number(chunk));
        const h = cb.call('blake3_hasher_create', null);
        let pieces = 0;
        let digest;
        try {
          for (let i = 0; i < data.length; i += step) {
            cb.call('blake3_hasher_update', h, data.subarray(i, i + step));
            pieces++;
          }
          digest = cb.call('blake3_hasher_finalize', h, Number(length));
        } finally {
          cb.call('blake3_hasher_free', h);
        }
        const oneShot = cb.call('blake3', data, Number(length));
        const short = cb.call('blake3', data, 32);
        return [
          row.text('Pieces fed', pieces),
          row.bytes('Incremental digest', digest),
          row.check('Same as hashing it in one call', same(digest, oneShot), 'identical'),
          row.check('Extendable output: the 32-byte digest is a prefix of the long one',
            Number(length) < 32 || same(short, oneShot.subarray(0, 32)), 'prefix'),
        ];
      },
    },
    {
      id: 'macs',
      title: 'Message authentication codes',
      statement: 'HMAC-SHA256, HMAC-SHA512, keyed BLAKE2b and keyed BLAKE3. Verification runs in constant time, and a MAC made with another key, or over another message, is refused.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'transfer 250 to account 7' }],
      run(cb, { message }) {
        const key = cb.call('random_bytes', 32);
        const other = cb.call('random_bytes', 32);
        const mac256 = cb.call('hmac_sha256', message, key);
        const mac512 = cb.call('hmac_sha512', message, key);
        const into = cb.Out.bytes(16);
        cb.call('blake2b_keyed_into', into, message, key);
        return [
          row.bytes('Key (fresh, 32 random bytes)', key),
          row.bytes('HMAC-SHA256', mac256),
          row.bytes('HMAC-SHA512', mac512),
          row.bytes('Keyed BLAKE2b, 16 bytes written in place', into.value),
          row.bytes('Keyed BLAKE3', cb.call('blake3_keyed', message, key, 32)),
          row.check('HMAC-SHA256 verifies', cb.call('hmac_sha256_verify', message, mac256, key) === 1, 'valid'),
          row.check('HMAC-SHA512 verifies', cb.call('hmac_sha512_verify', message, mac512, key) === 1, 'valid'),
          mustRefuse('A MAC under another key is refused', () => cb.call('hmac_sha256_verify', message, mac256, other)),
          mustRefuse('A MAC over an edited message is refused', () => cb.call('hmac_sha512_verify', `${message}0`, mac512, key)),
          row.check('Constant-time compare agrees', cb.call('secure_equal', mac256, mac256) === 1
            && cb.call('secure_equal', mac256, cb.call('hmac_sha256', message, other)) === 0, 'equal, then not'),
        ];
      },
    },
    {
      id: 'hkdf',
      title: 'One secret, many keys',
      statement: 'HKDF-SHA256 and BLAKE3 key derivation turn one shared secret into independent keys, one per purpose. Change the label and the key has nothing in common with the last.',
      inputs: [
        { name: 'secret', label: 'Shared secret', kind: 'text', value: 'the result of a key exchange' },
        { name: 'label', label: 'Purpose label', kind: 'text', value: 'chat/v1/send' },
      ],
      run(cb, { secret, label }) {
        const salt = utf8.encode('cipherbird demo salt');
        const prk = cb.call('hkdf_extract', salt, secret);
        const expanded = cb.call('hkdf_expand', prk, label, 32);
        const oneShot = cb.call('hkdf_derive', secret, salt, label, 32);
        const reply = cb.call('hkdf_derive', secret, salt, `${label}/reply`, 32);
        const b3 = cb.call('blake3_derive_key', label, secret, 32);
        return [
          row.bytes('Pseudorandom key (extract)', prk),
          row.bytes(`Key for "${label}"`, expanded),
          row.bytes(`Key for "${label}/reply"`, reply),
          row.bytes(`BLAKE3 derive_key("${label}")`, b3),
          row.check('Extract then expand equals the one-shot call', same(expanded, oneShot), 'identical'),
          row.check('Different labels give independent keys', bitDistance(expanded, reply) > 80, `${bitDistance(expanded, reply)} bits apart`),
        ];
      },
    },
    {
      id: 'argon2id',
      title: 'Passwords that are expensive to guess',
      statement: 'Argon2id stores a password as a self-describing PHC string with its own salt and cost. Raise the memory and every guess an attacker makes costs the same.',
      inputs: [
        { name: 'password', label: 'Password', kind: 'text', value: 'correct horse battery staple' },
        { name: 'memory', label: 'Memory (MiB)', kind: 'select', value: '16', options: ['8', '16', '32', '64'] },
      ],
      run(cb, { password, memory }) {
        const mem = Number(memory) * 1024 * 1024;
        const hashed = timed(() => utf8.decode(cb.call('argon2id_hash_str', password, 2, mem)));
        const again = utf8.decode(cb.call('argon2id_hash_str', password, 2, mem));
        const salt = cb.call('random_bytes', 16);
        const key = cb.call('argon2id_derive', password, salt, 32, 2, mem);
        return [
          row.text('PHC string', hashed.value),
          row.text('Time for one guess', `${hashed.ms.toFixed(0)} ms at ${memory} MiB`),
          row.check('The right password verifies', cb.call('argon2id_verify_str', password, hashed.value) === 1, 'valid'),
          mustRefuse('A wrong password is refused', () => cb.call('argon2id_verify_str', `${password}!`, hashed.value)),
          row.check('Same password, new salt, new string', hashed.value !== again, 'salted'),
          row.bytes('Key derived from the password and a salt', key),
        ];
      },
    },
    {
      id: 'random',
      title: 'Randomness from the engine',
      statement: 'random_bytes draws from the system generator through libsodium. Two draws never repeat; a crude frequency test shows the bytes are spread evenly.',
      inputs: [{ name: 'count', label: 'Bytes', kind: 'number', value: 4096, min: 64, max: 65536 }],
      run(cb, { count }) {
        const n = Number(count);
        const a = cb.call('random_bytes', n);
        const b = cb.call('random_bytes', n);
        const ones = Array.from(a).reduce((s, v) => s + bitDistance([v], [0]), 0);
        const ratio = ones / (n * 8);
        return [
          row.bytes('First draw', a.subarray(0, 32), `first 32 of ${n} bytes`),
          row.text('Share of one bits', `${(ratio * 100).toFixed(2)}%`),
          row.check('Two draws differ', !same(a, b), 'distinct'),
          row.check('Bits are balanced (within 2%)', Math.abs(ratio - 0.5) < 0.02, `${(ratio * 100).toFixed(2)}% ones`),
          row.text('Engine version', cb.call('version')),
          row.bytes('Concatenated digest of both draws', cb.call('sha256', concat(a, b))),
        ];
      },
    },
  ],
};
