import { row, mustRefuse, timed } from '../kit.js';
import { same, utf8, flipBit } from '../bytes.js';

const INTERACTIVE = 0;

function withVault(cb, master, fn) {
  const v = cb.call('vault_create', master, INTERACTIVE);
  try {
    return fn(v);
  } finally {
    cb.call('vault_free', v);
  }
}

function withEntropy(cb, path, deterministic, fn) {
  const e = cb.call(deterministic ? 'entropy_from_file_deterministic' : 'entropy_from_file', path);
  try {
    return fn(e);
  } finally {
    cb.call('entropy_free', e);
  }
}

function withEntropyVault(cb, e, fn) {
  const v = cb.call('vault_from_entropy', e, INTERACTIVE);
  try {
    return fn(v);
  } finally {
    cb.call('vault_free', v);
  }
}

export default {
  id: 'vault',
  title: 'Vault: sealed and signed packets',
  lead: 'The vault runs four layers in one call: Argon2id, a keyed BLAKE2b integrity tag, XChaCha20-Poly1305 and an Ed25519 signature. The asymmetric vault does the same from one person to another.',
  demos: [
    {
      id: 'seal-open',
      title: 'Four layers in one call',
      statement: 'A packet holds the ciphertext, an Ed25519 signature over it and the Argon2id salt. The signature is checked first, so a changed packet is refused before any key is derived.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'invoice 1042: 1,250.00 EUR due 2026-12-15' },
        { name: 'aad', label: 'Associated data', kind: 'text', value: 'tenant=acme' },
      ],
      run(cb, { message, aad }) {
        const master = cb.call('random_bytes', 32);
        return withVault(cb, master, (v) => {
          const sealed = timed(() => cb.call('vault_seal', v, message, aad));
          const packet = sealed.value;
          const opened = cb.call('vault_open', v, packet, aad);
          const forged = { ...packet, ciphertext: flipBit(packet.ciphertext, 40) };
          const badSig = { ...packet, signature: flipBit(packet.signature, 0) };
          const twin = withVault(cb, master, (w) => cb.call('vault_seal', w, message, aad));
          return [
            row.bytes('Vault signing key (vault_public_key)', cb.call('vault_public_key', v)),
            row.bytes('Ciphertext', packet.ciphertext, 'nonce, encrypted message and BLAKE2b tag, Poly1305 tag'),
            row.bytes('Signature', packet.signature, 'Ed25519 over the ciphertext'),
            row.bytes('Argon2id salt', packet.kdf_salt, 'fresh per packet'),
            row.text('Time to seal', `${sealed.ms.toFixed(0)} ms (interactive preset, 64 MiB)`),
            row.check('The vault opens its own packet', same(opened, utf8.encode(message)), utf8.decode(opened)),
            mustRefuse('Other associated data is refused', () => cb.call('vault_open', v, packet, `${aad}x`)),
            mustRefuse('One flipped ciphertext bit is refused', () => cb.call('vault_open', v, forged, aad)),
            mustRefuse('One flipped signature bit is refused', () => cb.call('vault_open', v, badSig, aad)),
            mustRefuse('A second vault with the same master key, but its own signing key, is refused',
              () => cb.call('vault_open', v, twin, aad)),
          ];
        });
      },
    },
    {
      id: 'packet-wire',
      title: 'A packet on the wire',
      statement: 'packet_serialise flattens a packet into one byte string for storage or transport, and packet_deserialise reads it back. Malformed bytes are refused when parsed; changed bytes are refused when opened.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'meeting moved to 15:30, room 4' }],
      run(cb, { message }) {
        return withVault(cb, cb.call('random_bytes', 32), (v) => {
          const packet = cb.call('vault_seal', v, message, 'calendar');
          const wire = cb.call('packet_serialise', packet);
          const back = cb.call('packet_deserialise', wire);
          const opened = cb.call('vault_open', v, back, 'calendar');
          const sizes = packet.ciphertext.length + packet.signature.length + packet.kdf_salt.length;
          return [
            row.bytes('Serialised packet', wire, `${wire.length} bytes, ${wire.length - sizes} of framing`),
            row.check('Deserialised fields match', same(back.ciphertext, packet.ciphertext)
              && same(back.signature, packet.signature) && same(back.kdf_salt, packet.kdf_salt), 'ciphertext, signature, salt'),
            row.check('Serialising again gives the same bytes', same(cb.call('packet_serialise', back), wire), 'stable'),
            row.check('The parsed packet opens', same(opened, utf8.encode(message)), utf8.decode(opened)),
            mustRefuse('Bytes cut inside the signature are refused by the parser', () => cb.call('packet_deserialise', wire.subarray(0, 40))),
            mustRefuse('Bytes cut from the end parse, then are refused when opened',
              () => cb.call('vault_open', v, cb.call('packet_deserialise', wire.subarray(0, wire.length - 10)), 'calendar')),
            mustRefuse('A flipped bit on the wire is refused when opened',
              () => cb.call('vault_open', v, cb.call('packet_deserialise', flipBit(wire, -80)), 'calendar')),
          ];
        });
      },
    },
    {
      id: 'asym',
      title: 'From Alice to Bob, signed',
      statement: 'Alice encrypts to Bob with X25519 and signs with Ed25519; Bob checks the signature with her public key. Nobody else can open it, and a packet that names another sender key is refused.',
      inputs: [
        { name: 'message', label: 'Message', kind: 'text', value: 'contract v7 attached, please countersign' },
        { name: 'aad', label: 'Associated data', kind: 'text', value: 'thread=88' },
      ],
      run(cb, { message, aad }) {
        const alice = cb.call('asym_bundle_generate');
        const bob = cb.call('asym_bundle_generate');
        const mallory = cb.call('asym_bundle_generate');
        const packet = cb.call('asym_vault_seal', alice, bob.box_public, message, aad);
        const opened = cb.call('asym_vault_open', packet, bob, alice.sign_public, aad);
        const swapped = { ...packet, kdf_salt: mallory.box_public };
        return [
          row.bytes('Alice X25519 public key', alice.box_public),
          row.bytes('Alice Ed25519 public key', alice.sign_public),
          row.bytes('Ciphertext', packet.ciphertext),
          row.bytes('Sender box key carried in the packet', packet.kdf_salt, 'signed together with the ciphertext'),
          row.check('Bob opens it with Alice\'s signing key', same(opened, utf8.encode(message)), utf8.decode(opened)),
          mustRefuse('Mallory cannot open it', () => cb.call('asym_vault_open', packet, mallory, alice.sign_public, aad)),
          mustRefuse('Checked against Mallory\'s signing key, it is refused', () => cb.call('asym_vault_open', packet, bob, mallory.sign_public, aad)),
          mustRefuse('Swapping in Mallory\'s box key is refused', () => cb.call('asym_vault_open', swapped, bob, alice.sign_public, aad)),
          mustRefuse('Other associated data is refused', () => cb.call('asym_vault_open', packet, bob, alice.sign_public, 'thread=89')),
        ];
      },
    },
    {
      id: 'from-entropy',
      title: 'A vault grown from a file',
      statement: 'vault_from_entropy keys a vault from a media file. Read in LavaRand mode the file is mixed with system randomness and every read gives new keys; read deterministically, the file itself is the key.',
      inputs: [{ name: 'size', label: 'Stand-in photo size (bytes)', kind: 'number', value: 4096, min: 256, max: 65536 }],
      run(cb, { size }) {
        const photo = cb.writeFile('/demo/vault/photo.raw', cb.call('random_bytes', Math.max(256, Number(size))));
        const other = cb.writeFile('/demo/vault/other.raw', cb.call('random_bytes', 4096));
        cb.writeFile('/demo/vault/tiny.raw', cb.call('random_bytes', 64));
        cb.writeFile('/demo/vault/blank.raw', new Uint8Array(4096));
        const lava = (path) => withEntropy(cb, path, false, (e) => withEntropyVault(cb, e, (v) => cb.call('vault_public_key', v)));
        const lavaA = lava(photo);
        const lavaB = lava(photo);
        const detKey = (path) => withEntropy(cb, path, true, (e) => withEntropyVault(cb, e, (v) => cb.call('vault_public_key', v)));
        const detA = detKey(photo);
        const detB = detKey(photo);
        const detOther = detKey(other);
        const crossOpen = withEntropy(cb, photo, true, (e1) => withEntropy(cb, photo, true, (e2) =>
          withEntropyVault(cb, e1, (v1) => withEntropyVault(cb, e2, (v2) =>
            cb.call('vault_open', v2, cb.call('vault_seal', v1, 'from the first read', ''), '')))));
        return [
          row.bytes('LavaRand read 1, vault signing key', lavaA),
          row.bytes('LavaRand read 2, vault signing key', lavaB),
          row.check('LavaRand mode: same file, new keys every read', !same(lavaA, lavaB), 'session keys'),
          row.bytes('Deterministic read, vault signing key', detA),
          row.check('Deterministic mode: same file, same keys', same(detA, detB) && !same(detA, detOther), 'the file is the key'),
          row.check('A second deterministic read opens the first one\'s packet', utf8.decode(crossOpen) === 'from the first read', utf8.decode(crossOpen)),
          mustRefuse('A file under 256 bytes is refused', () => cb.call('entropy_from_file', '/demo/vault/tiny.raw')),
          mustRefuse('A file of zeros fails the entropy floor', () => cb.call('entropy_from_file', '/demo/vault/blank.raw')),
        ];
      },
    },
    {
      id: 'boosted',
      title: 'Two factors: a key and a file',
      statement: 'A boosted seal mixes a file\'s entropy into the Argon2id input, so opening needs the vault and the file. In LavaRand mode the boost also carries system randomness and lives only as long as its handle.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'safe deposit box 3317, key with notary' }],
      run(cb, { message }) {
        const photo = cb.writeFile('/demo/boost/photo.raw', cb.call('random_bytes', 4096));
        const other = cb.writeFile('/demo/boost/other.raw', cb.call('random_bytes', 4096));
        return withVault(cb, cb.call('random_bytes', 32), (v) => {
          const packet = withEntropy(cb, photo, true, (e) => cb.call('vault_seal_boosted', v, message, 'box', e));
          const reread = withEntropy(cb, photo, true, (e) => cb.call('vault_open_boosted', v, packet, 'box', e));
          const rows = [
            row.bytes('Boosted packet ciphertext', packet.ciphertext),
            row.check('A fresh read of the same file opens it', same(reread, utf8.encode(message)), utf8.decode(reread)),
            mustRefuse('Without the file it is refused', () => cb.call('vault_open', v, packet, 'box')),
            mustRefuse('With another file it is refused', () => withEntropy(cb, other, true,
              (e) => cb.call('vault_open_boosted', v, packet, 'box', e))),
          ];
          withEntropy(cb, photo, false, (lava) => {
            const lp = cb.call('vault_seal_boosted', v, message, 'box', lava);
            rows.push(
              row.check('LavaRand boost: the same handle opens it', same(cb.call('vault_open_boosted', v, lp, 'box', lava), utf8.encode(message)), 'valid'),
              mustRefuse('LavaRand boost: a new read of the same file is refused', () => withEntropy(cb, photo, false,
                (again) => cb.call('vault_open_boosted', v, lp, 'box', again))),
            );
          });
          return rows;
        });
      },
    },
  ],
};
