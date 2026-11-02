# cipherbird

Native cryptography for Node.js. CipherBird binds its C++ engine through
koffi and ships the compiled library inside the package, so a program gets
hashing, authenticated encryption, public-key cryptography, post-quantum
algorithms, hybrid key agreement, sealed messaging, a secure channel,
password hashing, vaults, a keyring, anonymous credentials, threshold
signatures, media entropy and steganography from one dependency. It is the
Node.js twin of the [cipherbird](https://pub.dev/packages/cipherbird) and
[cipherbird_dart](https://pub.dev/packages/cipherbird_dart) packages: the
same engine, the same API names, the same wire formats, so an envelope
sealed here opens there.

| Area | What runs | Notes |
|---|---|---|
| Hashing | SHA-256, SHA-512, BLAKE2b, BLAKE3, Keccak-256, RIPEMD-160 | HMAC, HKDF, incremental BLAKE3 |
| Passwords | Argon2id | PHC strings, derived keys, three cost profiles |
| Symmetric | XChaCha20-Poly1305, AES-256-GCM, key-committing AEAD, SecretStream | the committing mode is the default in easy mode |
| Public key | X25519, Ed25519, boxes, sealed boxes, secp256k1 | EVM addresses and recovery |
| Post-quantum | ML-KEM, ML-DSA, SLH-DSA, sntrup761, X-Wing | FIPS 203, 204 and 205 through liboqs |
| Hybrid | X25519 plus ML-KEM-768, Ed25519 plus ML-DSA-65, X25519 plus sntrup761 | secure if either half holds |
| Protocols | sealed messaging, Noise XX, HPKE, OPAQUE, OPRF, BBS, FROST, ECVRF, BLS, session ratchets | composition of the primitives above |
| Storage | vaults, MolecularVault, keyring with device, passphrase and hardware slots | |
| Tokens | PASETO v4.local, cb1.local, cb1.public | v4.local byte for byte the specification; cb1 is CipherBird's own: BLAKE3 and the hybrid signature |
| Media | media entropy with a live stream source, DRBG, Fortuna, steganography, forward error correction | |

## Install

```bash
npm install cipherbird
```

| Platform | Status |
|---|---|
| macOS, Apple silicon | engine bundled under `prebuilds/darwin-arm64` |
| Linux x64, Windows x64, Intel macOS | not bundled in this release; build the library from the repository and point `CIPHERBIRD_LIBRARY` at it |

No setup call is needed. The engine loads on the first call, never at
`require` time; `preload()` warms it on a worker thread for programs that
want the first call to be instant. `CIPHERBIRD_LIBRARY` overrides the bundled
copy for development.

## Thirty seconds

```js
const cipherbird = require('cipherbird');

const key = cipherbird.SymmetricKey.generate();
const box = key.encryptText('meet at dawn', { aad: 'thread 7' });
console.log(key.decryptText(box, { aad: 'thread 7' }));

const signer = cipherbird.SigningKey.generate({ algorithm: 'hybrid' });
const signature = signer.signText('release 1.3.0');
console.log(signer.verifyKey.verifyText('release 1.3.0', signature));

const me = cipherbird.KemKeyPair.generate();
const blob = cipherbird.KemKeyPair.encryptTextFor(me.publicKey, 'for your eyes only');
console.log(me.decryptText(blob));

const phc = cipherbird.easy.hashPassword('correct horse battery staple');
console.log(cipherbird.easy.verifyPassword('correct horse battery staple', phc));
```

Easy mode picks the safe defaults: the key-committing AEAD, Argon2id at a
`SecurityProfile` cost, HKDF sub-keys, the post-quantum hybrid signature on
request. Everything below it is reachable by name.

## The surface

The flat API mirrors the Dart packages method for method, and the same
names are grouped by domain:

```js
cipherbird.hash.sha256(data);
cipherbird.aead.committingEncrypt(plaintext, key, aad);
cipherbird.pq.xwing.keygen();
cipherbird.suite.seal2(plaintext, recipient.publicKey, signer.secretKey, { aad });
cipherbird.sealed.newIdentity(cipherbird.SealedTier.Fortress);
cipherbird.rng.live().feed(cameraFrame);
```

| Namespace | What is in it |
|---|---|
| `hash` | SHA-2, BLAKE2b, BLAKE3 (one shot, keyed, derive, incremental), HMAC, HKDF, Argon2id, Keccak, RIPEMD |
| `aead` | XChaCha20-Poly1305, AES-256-GCM, the committing AEAD, SecretStream |
| `asym` | Ed25519, X25519, box, sealed box |
| `pq` | `mlKem`, `mlDsa`, `slhDsa`, `hybridKem`, `hybridSig`, `sntrup`, `xwing` |
| `bls`, `frost`, `ecvrf`, `bbs`, `oprf`, `opaque` | BLS12-381, FROST threshold signatures, ECVRF, BBS credentials, OPRF, OPAQUE |
| `hpke` | RFC 9180 with DHKEM(X25519), ML-KEM-768 or X-Wing |
| `sealed`, `session`, `channel` | Flagship and Fortress sealed messaging, the Session v1 and v2 ratchets, Noise XX |
| `suite` | one-call post-quantum seals, threshold seals, file-keyed and keyring-backed seals, Suite v2 |
| `vault`, `keyring` | layered vaults, MolecularVault, the keyring with device, passphrase and hardware slots |
| `entropy`, `rng` | media entropy, the health report, the entropy policy, the live source, DRBG, Fortuna |
| `stego`, `composed` | steganography across eleven carriers, the composed seals, forward error correction |
| `chain` | secp256k1, Keccak, EVM addresses and recovery |
| `fips` | the FIPS profile surface; `fips.available()` is false in this build |

Recipes compose the protections into one envelope that opens in every
CipherBird binding:

```js
const recipe = cipherbird.recipe('maximum')
  .withPassphrase('correct horse battery staple')
  .signedWith(signer.scheme)
  .verifiedWith(signer.verifyKey.scheme)
  .withFec(cipherbird.FecScheme.hamming74);
const envelope = recipe.seal(secret);
```

## Tokens

`pasetoV4LocalEncrypt` and `pasetoV4LocalDecrypt` are PASETO v4.local, byte
for byte the PASETO specification and checked against its official vectors.
`cb1LocalEncrypt`, `cb1LocalDecrypt`, `cb1PublicSign` and `cb1PublicVerify`
are cb1, CipherBird's own tokens: the same shape with BLAKE3 in place of
BLAKE2b and the Ed25519 + ML-DSA-65 hybrid signature in place of Ed25519.
The format is in the repository's `docs/CB1_TOKEN.md`; the pinned vectors
are shared with the C++, Go and Dart suites.

```js
const token = cipherbird.cb1LocalEncrypt(key, claims, kid, audience);
const back = cipherbird.cb1LocalDecrypt(token, key, kid, audience);
const signer = cipherbird.hybridSigKeygen();
const signed = cipherbird.cb1PublicSign(signer.secretKey, claims);
const verified = cipherbird.cb1PublicVerify(signed, signer.publicKey);
```

Every token-dependent failure throws one "invalid token" error, so a caller
cannot be used as an oracle; a key of the wrong length throws a RangeError.
`Paseto`, `Cb1` and the `tokens` namespace carry the length helpers too, and
every call runs on the worker through `cipherbird.async`. `blake2bKeyed`
computes BLAKE2b at a chosen length and `blake2bKeyedInto` fills a buffer.

## Media on bytes

Every file-taking media method has a twin on bytes, so a carrier held in
memory works without the caller managing paths. The format names the
carrier's container by MediaFormat name, wire value or bare extension:

```js
const hidden = cipherbird.stegoEmbedBytes(photo, 'pngImage', payload);
const back = cipherbird.stegoExtractBytes(hidden, 'png');
const verdict = cipherbird.assessHealthOf(photo);
console.log(verdict.summary);
const envelope = cipherbird.recipe().withKeySource(new cipherbird.KeyBytesSource(photo)).seal(secret);
```

Bytes pass through a private temporary directory that is overwritten and
removed after each call.

## Live entropy

A continuous source for a stream: feed camera frames, audio buffers or any
bytes as they arrive. Each chunk is assessed under the policy, credited when
it passes and mixed in without credit when it does not, with the reason
reported; `generate` draws from an HMAC-DRBG seeded after 256 credited bits
and throws until then.

```js
const live = cipherbird.liveEntropy();
const report = live.feed(frame, 1);
if (report.accepted) console.log(live.generate(32));
else console.log(report.reason);
live.close();
```

## Off the main thread

`cipherbird.async.<method>(...args)` runs any data-in, data-out method of
the flat API on one long-lived worker thread and resolves with its result:

```js
const envelope = await cipherbird.async.suite2Seal(plaintext, recipient.publicKey, signer.secretKey);
const key = await cipherbird.easy.symmetricKeyFromPassphraseAsync(passphrase, { salt });
```

Native handles (keyrings, vaults, sessions, contexts) stay on the thread
that made them. The worker is unreferenced while idle and never keeps the
process alive.

## Secrets

`wipe(buffer)` zeros a buffer; `Secret.take(bytes)` wraps key material so
that `wipe()` zeros it and every later access throws. `SymmetricKey`,
`SigningKey` and `KemKeyPair` have `destroy()`. Passwords given as Buffers
are passed to the engine by pointer and the NUL-terminated copy is wiped
afterwards.

## Tests

```bash
npm test
```

runs the smoke, parity, bytes, easy-mode, namespace, worker, security,
Noise, extensibility and BBS suites and the three demos against the bundled
engine. The parity suite checks that every function in the engine's C header
is declared by the binding when the header is reachable.

## Licence

MIT. The engine is built from the
[CipherBird](https://github.com/Crdzbird/CipherBird) repository, where the
threat model, the benchmarks and the other bindings live.
