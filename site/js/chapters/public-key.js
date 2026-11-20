import { row, mustRefuse, refuses, bitDistance } from '../kit.js';
import { hex, fromHex, same, utf8, concat, flipBit } from '../bytes.js';

const RFC8032_SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const RFC8032_PUBLIC = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const RFC8032_SIGNATURE = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015'
  + '55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

const RFC7748 = {
  aliceSecret: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
  alicePublic: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
  bobSecret: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
  bobPublic: 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
  shared: '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
};

const SECP256K1_G = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
const ADDRESS_OF_KEY_ONE = '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf';

const P256_FIXTURE_DER = '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042063e0acc0eb9f737b59abc9443e8ea418ee738c'
  + 'e2f317f92c72e48e36a7751476a14403420004a4726836c202048a75e72da9d3e3c934ef7e244bb52de7e416c6c81760ab9ebe30be4dc0'
  + '5f6b517af45089b58ee65ae350e3dbc61ed592a3121110fa385777d8';
const P256_FIXTURE_SK = '63e0acc0eb9f737b59abc9443e8ea418ee738ce2f317f92c72e48e36a7751476';
const P256_FIXTURE_PK = '04a4726836c202048a75e72da9d3e3c934ef7e244bb52de7e416c6c81760ab9ebe30be4dc05f6b517af45089b58ee65ae350e3dbc61ed5'
  + '92a3121110fa385777d8';
const P256_FIXTURE_PEM = '-----BEGIN PRIVATE KEY-----\n'
  + 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgY+CswOufc3tZq8lE\n'
  + 'Po6kGO5zjOLzF/kscuSONqd1FHahRANCAASkcmg2wgIEinXnLanT48k0734kS7Ut\n'
  + '5+QWxsgXYKuevjC+TcBfa1F69FCJtY7mWuNQ49vGHtWSoxIREPo4V3fY\n'
  + '-----END PRIVATE KEY-----\n';

function eip55(cb, address) {
  const lower = hex(address);
  const digest = hex(cb.call('keccak256', lower));
  let out = '0x';
  for (let i = 0; i < lower.length; i++) {
    out += parseInt(digest[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

function personalDigest(cb, message) {
  const body = utf8.encode(message);
  return cb.call('keccak256', concat(utf8.encode(`\x19Ethereum Signed Message:\n${body.length}`), body));
}

export default {
  id: 'public-key',
  title: 'Public-key cryptography',
  lead: 'Signatures with Ed25519, secp256k1 and P-256, key agreement with X25519, and public-key encryption with Box and sealed boxes. Every key on this page is made by the engine in your browser.',
  demos: [
    {
      id: 'ed25519',
      title: 'Sign and verify with Ed25519',
      statement: 'A 64-byte signature proves who wrote a message and that it was not changed. Anyone with the 32-byte public key can check it.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'release 4.2.0 is signed by the build key' }],
      run(cb, { message }) {
        const kp = cb.call('ed25519_keygen');
        const other = cb.call('ed25519_keygen');
        const sig = cb.call('ed25519_sign', message, kp.secret_key);
        return [
          row.bytes('Public key', kp.public_key),
          row.bytes('Signature', sig),
          row.text('Sizes', `public key ${kp.public_key.length} B, secret key ${kp.secret_key.length} B, signature ${sig.length} B`),
          row.check('The signature verifies', cb.call('ed25519_verify', message, sig, kp.public_key) === 1, 'valid'),
          row.check('Signing is deterministic: the same message gives the same signature',
            same(sig, cb.call('ed25519_sign', message, kp.secret_key)), 'identical'),
          mustRefuse('An edited message is refused', () => cb.call('ed25519_verify', `${message}.`, sig, kp.public_key)),
          mustRefuse('A signature with one bit flipped is refused', () => cb.call('ed25519_verify', message, flipBit(sig, 10), kp.public_key)),
          mustRefuse('Another public key does not accept it', () => cb.call('ed25519_verify', message, sig, other.public_key)),
        ];
      },
    },
    {
      id: 'ed25519-seed',
      title: 'The same seed, the same key',
      statement: 'An Ed25519 key pair is fully determined by a 32-byte seed. Back up the seed and the key can be rebuilt anywhere, bit for bit.',
      inputs: [{ name: 'phrase', label: 'Phrase hashed into a seed', kind: 'text', value: 'orbit lantern copper meadow' }],
      run(cb, { phrase }) {
        const seed = cb.call('sha256', phrase);
        const a = cb.call('ed25519_keygen_from_seed', seed);
        const b = cb.call('ed25519_keygen_from_seed', seed);
        const c = cb.call('ed25519_keygen_from_seed', flipBit(seed, 0));
        const rfc = cb.call('ed25519_keygen_from_seed', fromHex(RFC8032_SEED));
        const rfcSig = cb.call('ed25519_sign', new Uint8Array(0), rfc.secret_key);
        return [
          row.bytes('Seed = SHA-256 of the phrase', seed),
          row.bytes('Public key', a.public_key),
          row.check('The same seed gives the same key pair', same(a.public_key, b.public_key) && same(a.secret_key, b.secret_key), 'identical'),
          row.check('The 64-byte secret key is the seed followed by the public key',
            same(a.secret_key, concat(seed, a.public_key)), 'seed || public key'),
          row.check('A seed one bit away gives an unrelated key', bitDistance(a.public_key, c.public_key) > 80,
            `${bitDistance(a.public_key, c.public_key)} of 256 bits differ`),
          row.check('RFC 8032 test 1: the public key matches', hex(rfc.public_key) === RFC8032_PUBLIC, 'known answer'),
          row.check('RFC 8032 test 1: the signature of the empty message matches', hex(rfcSig) === RFC8032_SIGNATURE, 'known answer'),
        ];
      },
    },
    {
      id: 'x25519',
      title: 'Two parties, one secret',
      statement: 'With X25519 each side combines its own secret key with the other public key and both arrive at the same 32 bytes. An eavesdropper who sees both public keys cannot.',
      inputs: [],
      run(cb) {
        const alice = cb.call('x25519_keygen');
        const bob = cb.call('x25519_keygen');
        const eve = cb.call('x25519_keygen');
        const ab = cb.call('x25519_shared_secret', alice.secret_key, bob.public_key);
        const ba = cb.call('x25519_shared_secret', bob.secret_key, alice.public_key);
        const ea = cb.call('x25519_shared_secret', eve.secret_key, alice.public_key);
        const kat1 = cb.call('x25519_shared_secret', fromHex(RFC7748.aliceSecret), fromHex(RFC7748.bobPublic));
        const kat2 = cb.call('x25519_shared_secret', fromHex(RFC7748.bobSecret), fromHex(RFC7748.alicePublic));
        return [
          row.bytes('Alice public key', alice.public_key),
          row.bytes('Bob public key', bob.public_key),
          row.bytes('Alice computes', ab),
          row.bytes('Bob computes', ba),
          row.check('Both sides agree', same(ab, ba), 'identical'),
          row.check('Eve, pairing her own key with Alice, gets something else', !same(ea, ab), 'different'),
          row.check('RFC 7748 section 6.1: both directions give the published secret',
            hex(kat1) === RFC7748.shared && hex(kat2) === RFC7748.shared, 'known answer'),
          mustRefuse('An all-zero (low-order) public key is refused', () => cb.call('x25519_shared_secret', alice.secret_key, new Uint8Array(32))),
          row.text('Note', 'The raw X25519 output is not a cipher key. Hash it or feed it to HKDF first, as Box and HPKE do.'),
        ];
      },
    },
    {
      id: 'box',
      title: 'Box: encrypt to someone you know',
      statement: 'Box encrypts from one key pair to another and authenticates the sender at the same time. A message forged under another sender key is refused.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'the shipment leaves on Thursday' }],
      run(cb, { message }) {
        const alice = cb.call('box_keygen');
        const bob = cb.call('box_keygen');
        const mallory = cb.call('box_keygen');
        const ct = cb.call('box_encrypt', message, bob.public_key, alice.secret_key);
        const forged = cb.call('box_encrypt', message, bob.public_key, mallory.secret_key);
        const opened = utf8.decode(cb.call('box_decrypt', ct, alice.public_key, bob.secret_key));
        const back = utf8.decode(cb.call('box_decrypt', ct, bob.public_key, alice.secret_key));
        const overhead = ct.length - utf8.encode(message).length;
        return [
          row.bytes('Ciphertext (nonce, then encrypted text and tag)', ct),
          row.text('Overhead', `${overhead} bytes: a 24-byte random nonce and a 16-byte tag`),
          row.check('Bob opens it with Alice public key', opened === message, opened),
          row.check('Overhead is 40 bytes', overhead === 40, `${overhead} bytes`),
          mustRefuse('A box Mallory made, presented as from Alice, is refused', () => cb.call('box_decrypt', forged, alice.public_key, bob.secret_key)),
          mustRefuse('A tampered ciphertext is refused', () => cb.call('box_decrypt', flipBit(ct, -1), alice.public_key, bob.secret_key)),
          row.check('Alice can open her own box too: the key is shared, so Box proves origin to Bob only', back === message, 'opened'),
        ];
      },
    },
    {
      id: 'sealed-box',
      title: 'Sealed box: anonymous sender',
      statement: 'A sealed box needs only the recipient public key, so it carries no sender identity at all. Only the holder of the matching secret key can open it.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'an anonymous tip for the newsroom' }],
      run(cb, { message }) {
        const recipient = cb.call('box_keygen');
        const stranger = cb.call('box_keygen');
        const a = cb.call('sealedbox_encrypt', message, recipient.public_key);
        const b = cb.call('sealedbox_encrypt', message, recipient.public_key);
        const opened = utf8.decode(cb.call('sealedbox_decrypt', a, recipient.public_key, recipient.secret_key));
        const overhead = a.length - utf8.encode(message).length;
        return [
          row.bytes('Sealed box', a),
          row.text('Overhead', `${overhead} bytes: a one-time public key (32) and a tag (16)`),
          row.check('The recipient opens it', opened === message, opened),
          row.check('Sealing twice gives unrelated boxes, so equal messages cannot be linked', !same(a, b), 'different'),
          mustRefuse('Another key pair cannot open it', () => cb.call('sealedbox_decrypt', a, stranger.public_key, stranger.secret_key)),
          mustRefuse('A flipped bit is refused', () => cb.call('sealedbox_decrypt', flipBit(a, 40), recipient.public_key, recipient.secret_key)),
        ];
      },
    },
    {
      id: 'evm-address',
      title: 'From a secp256k1 key to an Ethereum address',
      statement: 'An EVM address is the last 20 bytes of the Keccak-256 hash of the public key, without its 0x04 prefix. The engine derives it, and the same steps by hand agree.',
      inputs: [],
      run(cb) {
        const kp = cb.call('secp256k1_keygen');
        const address = cb.call('suite_evm_address', kp.public_key);
        const byHand = cb.call('keccak256', kp.public_key.subarray(1)).subarray(12);
        const compressed = cb.call('secp256k1_pubkey', kp.secret_key, 1);
        const one = new Uint8Array(32);
        one[31] = 1;
        const g = cb.call('secp256k1_pubkey', one, 0);
        return [
          row.bytes('Secret key', kp.secret_key),
          row.bytes('Public key, uncompressed (0x04, X, Y)', kp.public_key),
          row.bytes('Public key, compressed (parity byte, X)', compressed),
          row.text('Address (EIP-55 checksum)', eip55(cb, address)),
          row.check('keccak256(X || Y), last 20 bytes, equals the engine address', same(address, byHand), 'identical'),
          row.check('Deriving the public key again gives the key pair public key',
            same(cb.call('secp256k1_pubkey', kp.secret_key, 0), kp.public_key), 'identical'),
          row.check('Compressed form is the parity byte and X', compressed.length === 33
            && compressed[0] === 2 + (kp.public_key[64] & 1) && same(compressed.subarray(1), kp.public_key.subarray(1, 33)), `${compressed.length} bytes`),
          row.check('Secret key 1 gives the generator point G', hex(g) === SECP256K1_G, 'known answer'),
          row.check(`Secret key 1 gives address ${ADDRESS_OF_KEY_ONE}`,
            eip55(cb, cb.call('suite_evm_address', g)) === ADDRESS_OF_KEY_ONE, 'known answer, with checksum'),
          mustRefuse('A compressed key is refused: the address needs the full point', () => cb.call('suite_evm_address', compressed)),
        ];
      },
    },
    {
      id: 'ecrecover',
      title: 'Recover the signer from the signature',
      statement: 'A secp256k1 signature with its recovery id gives back the public key that made it. That is how Ethereum learns the sender address without being told.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: 'I agree to the terms, nonce 41' }],
      run(cb, { message }) {
        const kp = cb.call('secp256k1_keygen');
        const digest = personalDigest(cb, message);
        const sig = cb.call('secp256k1_sign', digest, kp.secret_key);
        const recovered = cb.call('secp256k1_recover', digest, sig);
        const other = personalDigest(cb, `${message}!`);
        const fromOther = refuses(() => cb.call('secp256k1_recover', other, sig));
        return [
          row.bytes('Digest = keccak256 of the EIP-191 personal message', digest),
          row.bytes('Signature r || s || recovery id', sig),
          row.text('Recovery id', `${sig[64]} (Ethereum v = ${27 + sig[64]})`),
          row.text('Signer address', eip55(cb, cb.call('suite_evm_address', kp.public_key))),
          row.check('The 64-byte r || s verifies', cb.call('secp256k1_verify', digest, sig.subarray(0, 64), kp.public_key) === 1, 'valid'),
          row.check('It also verifies against the compressed key',
            cb.call('secp256k1_verify', digest, sig.subarray(0, 64), cb.call('secp256k1_pubkey', kp.secret_key, 1)) === 1, 'valid'),
          row.check('Recovery returns the signer public key, so the same address', same(recovered, kp.public_key), eip55(cb, cb.call('suite_evm_address', recovered))),
          row.check('RFC 6979 nonces: signing again gives the same signature', same(sig, cb.call('secp256k1_sign', digest, kp.secret_key)), 'identical'),
          row.check('For an edited message, recovery names someone else or fails',
            fromOther.refused || !same(fromOther.value, kp.public_key), fromOther.refused ? 'refused' : 'another key'),
          mustRefuse('The signature does not verify over an edited message', () => cb.call('secp256k1_verify', other, sig.subarray(0, 64), kp.public_key)),
        ];
      },
    },
    {
      id: 'p256',
      title: 'P-256 for JWS ES256',
      statement: 'P-256 ECDSA over SHA-256 is the ES256 algorithm of JWS and Apple push tokens. It runs in OpenSSL, so it is present only where the engine was built with its elliptic curves.',
      inputs: [{ name: 'message', label: 'Message', kind: 'text', value: '{"iss":"TEAM123","iat":1700000000}' }],
      run(cb, { message }) {
        const mode = cb.call('p256_available');
        if (mode === 0) {
          const kp = cb.call('p256_keygen');
          const sk = fromHex(P256_FIXTURE_SK);
          return [
            row.text('Available in this engine', 'no: this WebAssembly engine is built with a trimmed libcrypto without elliptic curves'),
            row.check('Key generation returns no key rather than a fake one', kp.public_key.length === 0 && kp.secret_key.length === 0, 'empty'),
            mustRefuse('Deriving a public key reports the feature as missing', () => cb.call('p256_public_key', sk)),
            mustRefuse('Signing reports the feature as missing', () => cb.call('p256_sign', sk, message)),
            mustRefuse('Verification answers no', () => cb.call('p256_verify', fromHex(P256_FIXTURE_PK), message, new Uint8Array(64))),
            mustRefuse('PKCS#8 DER import reports the feature as missing', () => cb.call('p256_import_pkcs8_der', fromHex(P256_FIXTURE_DER))),
            mustRefuse('PKCS#8 PEM import reports the feature as missing', () => cb.call('p256_import_pkcs8_pem', P256_FIXTURE_PEM)),
            row.text('Where it runs', 'The native full and bank engines carry P-256; the fips profile has its own FIPS P-256 functions.'),
          ];
        }
        const kp = cb.call('p256_keygen');
        const sig = cb.call('p256_sign', kp.secret_key, message);
        const der = cb.call('p256_import_pkcs8_der', fromHex(P256_FIXTURE_DER));
        const pem = cb.call('p256_import_pkcs8_pem', P256_FIXTURE_PEM);
        return [
          row.text('Available in this engine', mode === 2 ? 'yes, with deterministic RFC 6979 nonces' : 'yes, with hedged random nonces'),
          row.bytes('Public key (0x04, X, Y)', kp.public_key),
          row.bytes('Signature r || s', sig),
          row.check('The public key derives from the secret key', same(cb.call('p256_public_key', kp.secret_key), kp.public_key), 'identical'),
          row.check('The signature verifies', cb.call('p256_verify', kp.public_key, message, sig) === 1, 'valid'),
          mustRefuse('An edited message is refused', () => cb.call('p256_verify', kp.public_key, `${message} `, sig)),
          row.check('PKCS#8 DER import gives the secret key and its public key', same(der, concat(fromHex(P256_FIXTURE_SK), fromHex(P256_FIXTURE_PK))), `${der.length} bytes`),
          row.check('The PEM form of the same key imports to the same bytes', same(pem, der), 'identical'),
          mustRefuse('A DER with a trailing byte is refused', () => cb.call('p256_import_pkcs8_der', concat(fromHex(P256_FIXTURE_DER), [0]))),
        ];
      },
    },
  ],
};
