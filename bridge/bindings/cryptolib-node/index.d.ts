/**
 * CipherBird for Node.js: the CryptoLib engine over koffi, with the same
 * surface as the cipherbird Dart packages. Every byte argument accepts a
 * Buffer, a Uint8Array or a string (UTF-8); every byte result is a Buffer.
 */

export type Bytes = Buffer | Uint8Array | string;
export type Handle = unknown;

export interface KeyPair { publicKey: Buffer; secretKey: Buffer; }
export interface Encapsulation { ciphertext: Buffer; sharedSecret: Buffer; }
export interface Packet { ciphertext: Buffer; signature: Buffer; kdfSalt: Buffer; }
export interface AsymBundle { boxPublic: Buffer; boxSecret: Buffer; signPublic: Buffer; signSecret: Buffer; }
export interface DerivedKeys {
  symmetricKey: Buffer; vaultMasterKey: Buffer; signingSeed: Buffer; boxSeed: Buffer; streamKey: Buffer; rawEntropy: Buffer;
}
export interface EntropyInfo { path: string; fileSize: number; chunksRead: number; entropyBits: number; }
export interface SealedInfo { version: number; suite: number; streaming: boolean; fingerprint: Buffer; kemCiphertextLen: number; }
export interface SealedOptions { aad?: Bytes | null; purpose?: Bytes | null; }

/** Overwrite a Buffer or typed array with zeros. */
export function wipe<T extends { fill(v: number): unknown }>(bytes: T): T;

/** Secret material with a definite end of life: wipe() zeros it and every later access throws. */
export class Secret {
  constructor(bytes: Bytes);
  static take(bytes: Bytes): Secret;
  static copy(bytes: Bytes): Secret;
  readonly bytes: Buffer;
  readonly length: number;
  readonly wiped: boolean;
  wipe(): void;
}
export const SecretBytes: typeof Secret;

export function init(): void;
export function version(): string;
/** Warm the engine on a worker thread; the synchronous API never needs it. */
export function preload(): Promise<boolean>;
export function randomBytes(n: number): Buffer;

export function sha256(m: Bytes): Buffer;
export function sha512(m: Bytes): Buffer;
export function blake2b(m: Bytes, key?: Bytes | null): Buffer;
export function blake3(m: Bytes, len?: number): Buffer;
export function blake3Keyed(m: Bytes, key: Bytes, len?: number): Buffer;
export function blake3DeriveKey(context: string, ikm: Bytes, len?: number): Buffer;
export function hmacSha256(m: Bytes, key: Bytes): Buffer;
export function hmacSha256Verify(m: Bytes, mac: Bytes, key: Bytes): boolean;
export function hmacSha512(m: Bytes, key: Bytes): Buffer;
export function hmacSha512Verify(m: Bytes, mac: Bytes, key: Bytes): boolean;
export function hkdfDerive(ikm: Bytes, opts?: { salt?: Bytes | null; info?: Bytes | null; outLen?: number }): Buffer;
export function hkdfExtract(ikm: Bytes, salt?: Bytes | null): Buffer;
export function hkdfExpand(prk: Bytes, info?: Bytes | null, len?: number): Buffer;
export function argon2idHashStr(password: Bytes, ops?: number, mem?: number): string;
export function argon2idVerifyStr(password: Bytes, phc: string): boolean;
export function argon2idDerive(password: Bytes, salt: Bytes, keyLen?: number, ops?: number, mem?: number): Buffer;
export function keccak256(m: Bytes): Buffer;
export function ripemd160(m: Bytes): Buffer;
export function secureEqual(a: Bytes, b: Bytes): boolean;

export function symKeygen(): Buffer;
export function xchacha20Encrypt(pt: Bytes, key: Bytes, aad?: Bytes | null): Buffer;
export function xchacha20Decrypt(ct: Bytes, key: Bytes, aad?: Bytes | null): Buffer;
export function aes256gcmAvailable(): boolean;
export function aes256gcmEncrypt(pt: Bytes, key: Bytes, aad?: Bytes | null): Buffer;
export function aes256gcmDecrypt(ct: Bytes, key: Bytes, aad?: Bytes | null): Buffer;
export function committingEncrypt(pt: Bytes, key: Bytes, aad?: Bytes | null): Buffer;
export function committingDecrypt(ct: Bytes, key: Bytes, aad?: Bytes | null): Buffer;
export function streamEncryptorCreate(key: Bytes): Handle;
export function streamEncHeader(h: Handle): Buffer;
export function streamEncPush(h: Handle, pt: Bytes, tag?: number): Buffer;
export function streamEncFree(h: Handle): void;
export function streamDecryptorCreate(key: Bytes, header: Bytes): Handle;
export function streamDecPull(h: Handle, ct: Bytes): { plaintext: Buffer; tag: number };
export function streamDecFree(h: Handle): void;
/** SecretStream over a list of chunks; the last chunk carries the FINAL tag. */
export function streamEncrypt(key: Bytes, chunks: Bytes[]): { header: Buffer; chunks: Buffer[] };
export function streamDecrypt(key: Bytes, header: Bytes, chunks: Bytes[]): Buffer[];

export function ed25519Keygen(): KeyPair;
export function ed25519KeygenFromSeed(seed: Bytes): KeyPair;
export function ed25519Sign(m: Bytes, sk: Bytes): Buffer;
export function ed25519Verify(m: Bytes, sig: Bytes, pk: Bytes): boolean;
export function x25519Keygen(): KeyPair;
export function x25519SharedSecret(sk: Bytes, pk: Bytes): Buffer;
export function boxKeygen(): KeyPair;
export function boxEncrypt(pt: Bytes, recipientPub: Bytes, senderSec: Bytes): Buffer;
export function boxDecrypt(ct: Bytes, senderPub: Bytes, recipientSec: Bytes): Buffer;
export function sealedboxEncrypt(pt: Bytes, recipientPub: Bytes): Buffer;
export function sealedboxDecrypt(ct: Bytes, recipientPub: Bytes, recipientSec: Bytes): Buffer;
export function secp256k1Keygen(): KeyPair;
export function secp256k1Pubkey(sk: Bytes, compressed?: boolean): Buffer;
export function secp256k1Sign(digest32: Bytes, sk: Bytes): Buffer;
export function secp256k1Verify(digest32: Bytes, sig: Bytes, pk: Bytes): boolean;
export function secp256k1Recover(digest32: Bytes, sig65: Bytes): Buffer;

/** ML-KEM level: 0 = 512, 1 = 768, 2 = 1024. */
export function mlKemKeygen(level?: number): KeyPair;
export function mlKemEncapsulate(pk: Bytes, level?: number): Encapsulation;
export function mlKemDecapsulate(ct: Bytes, sk: Bytes, level?: number): Buffer;
/** ML-DSA level: 0 = 44, 1 = 65, 2 = 87. */
export function mlDsaKeygen(level?: number): KeyPair;
export function mlDsaSign(m: Bytes, sk: Bytes, level?: number): Buffer;
export function mlDsaVerify(m: Bytes, sig: Bytes, pk: Bytes, level?: number): boolean;
/** SLH-DSA level 0..5 and hash family 0 = SHA2, 1 = SHAKE. */
export function slhDsaKeygen(level?: number, hashFamily?: number): KeyPair;
export function slhDsaSign(m: Bytes, sk: Bytes, level?: number, hashFamily?: number): Buffer;
export function slhDsaVerify(m: Bytes, sig: Bytes, pk: Bytes, level?: number, hashFamily?: number): boolean;
export function hybridKemKeygen(): KeyPair;
export function hybridKemEncapsulate(pk: Bytes): Encapsulation;
export function hybridKemDecapsulate(ct: Bytes, sk: Bytes): Buffer;
export function sntrupX25519Keygen(): KeyPair;
export function sntrupX25519Encapsulate(pk: Bytes): Encapsulation;
export function sntrupX25519Decapsulate(ct: Bytes, sk: Bytes): Buffer;
export function hybridSigKeygen(): KeyPair;
export function hybridSigSign(m: Bytes, sk: Bytes): Buffer;
export function hybridSigVerify(m: Bytes, sig: Bytes, pk: Bytes): boolean;
export function blsKeygen(): KeyPair;
export function blsKeygenFromIkm(ikm: Bytes): KeyPair;
export function blsSign(m: Bytes, sk: Bytes): Buffer;
export function blsVerify(m: Bytes, sig: Bytes, pk: Bytes): boolean;
export function blsAggregate(sigs: Bytes[]): Buffer;
export function blsAggregateVerify(msgs: Bytes[], pks: Bytes[], agg: Bytes): boolean;

/** X-Wing (ML-KEM-768 + X25519): public key 1216 bytes, secret key the 32-byte seed. */
export const XWing: {
  keygen(): KeyPair;
  keypairFromSeed(seed: Bytes): KeyPair;
  encapsulate(publicKey: Bytes): Encapsulation;
  decapsulate(ciphertext: Bytes, secretKey: Bytes): Buffer;
};
export function xwingKeygen(): KeyPair;
export function xwingKeypairFromSeed(seed: Bytes): KeyPair;
export function xwingEncapsulate(publicKey: Bytes): Encapsulation;
export function xwingDecapsulate(ciphertext: Bytes, secretKey: Bytes): Buffer;

export function keyringCreate(): Handle;
export function keyringAddDeviceSlot(kr: Handle, factor: Bytes): boolean;
export function keyringAddPassphraseSlot(kr: Handle, passphrase: Bytes, kdf?: number): boolean;
export function keyringSlotCount(kr: Handle): number;
export function keyringSerialise(kr: Handle): Buffer;
export function keyringDeserialise(blob: Bytes): Handle;
export function keyringUnlockWithDevice(kr: Handle, factor: Bytes): Buffer;
export function keyringUnlockWithPassphrase(kr: Handle, passphrase: Bytes): Buffer;
export function keyringRemoveSlot(kr: Handle, index: number): boolean;
export function keyringFree(kr: Handle): void;
export const KeyringSlotType: { readonly passphrase: 0; readonly device: 1; readonly hardware: 2 };
/** Add a hardware slot named by keyId; returns the fresh 32-byte factor for the platform key module to wrap. */
export function keyringAddHardwareSlot(kr: Handle, keyId: Bytes): Buffer;
export function keyringSetHardwareBlob(kr: Handle, index: number, blob: Bytes): boolean;
export function keyringSlotType(kr: Handle, index: number): number;
export function keyringHardwareSlot(kr: Handle, index: number): { keyId: Buffer; blob: Buffer };
export function keyringUnlockWithHardware(kr: Handle, index: number, factor: Bytes): Buffer;

export function vaultCreate(masterKey: Bytes, kdf?: number): Handle;
export function vaultFromEntropy(h: Handle, kdf?: number): Handle;
export function vaultPublicKey(v: Handle): Buffer;
export function vaultSeal(v: Handle, pt: Bytes, aad?: string): Packet;
export function vaultOpen(v: Handle, pkt: Packet, aad?: string): Buffer;
export function vaultSealBoosted(v: Handle, pt: Bytes, aad: string, boost: Handle): Packet;
export function vaultOpenBoosted(v: Handle, pkt: Packet, aad: string, boost: Handle): Buffer;
export function vaultFree(v: Handle): void;
export function packetSerialise(pkt: Packet): Buffer;
export function packetDeserialise(data: Bytes): Packet;
export function asymBundleGenerate(): AsymBundle;
export function asymVaultSeal(sender: AsymBundle, recipientBoxPub: Bytes, pt: Bytes, aad?: string): Packet;
export function asymVaultOpen(pkt: Packet, recipient: AsymBundle, senderSignPub: Bytes, aad?: string): Buffer;
export function molecularSeal(pt: Bytes, passphrase: Bytes, aad?: Bytes | null, ops?: number, mem?: number): Buffer;
export function molecularOpen(env: Bytes, passphrase: Bytes, aad?: Bytes | null): Buffer;
export function molecularSealWithKey(pt: Bytes, masterKey: Bytes, aad?: Bytes | null): Buffer;
export function molecularOpenWithKey(env: Bytes, masterKey: Bytes, aad?: Bytes | null): Buffer;

export function entropyFromFile(path: string): Handle;
export function entropyFromFileDeterministic(path: string): Handle;
export function entropyFromFiles(paths: string[]): Handle;
export function entropyFromFilesDeterministic(paths: string[]): Handle;
export interface EntropyPolicy { deterministic?: boolean; minBitsPerByte?: number; requireRct?: boolean; }
/** Harvest under a policy: refused below minBitsPerByte of min-entropy (0 accepts any file) and, with requireRct, on a failed repetition-count test. */
export function entropyFromFileWithPolicy(path: string, policy?: EntropyPolicy): Handle;
export function entropyFromBytes(bytes: Bytes, policy?: EntropyPolicy & { extension?: string }): Handle;
export function entropyDeriveAll(h: Handle): DerivedKeys;
export function entropySymmetricKey(h: Handle): Buffer;
export function entropyRaw(h: Handle): Buffer;
export function entropyBoost(h: Handle): Buffer;
export function entropyInfo(h: Handle): EntropyInfo;
export function entropyRefresh(h: Handle): void;
export function entropyAsymBundle(h: Handle): AsymBundle;
export function entropyFree(h: Handle): void;
export function keyFromFile(path: string): Buffer;
export function keyFromBytes(bytes: Bytes): Buffer;
export function sealFromFile(path: string, plaintext: string, aad?: string): Packet;
export function openFromFile(path: string, pkt: Packet, aad?: string): Buffer;
export function sealWithBytes(bytes: Bytes, plaintext: string, aad?: string): Packet;
export function openWithBytes(bytes: Bytes, pkt: Packet, aad?: string): Buffer;

/** The SP 800-90B verdict with every number behind it. */
export interface HealthReport {
  minEntropyPerByte: number; mcvBitsPerByte: number; markovBitsPerByte: number; floorBitsPerByte: number;
  sampleBytes: number; longestRun: number; rctCutoff: number; maxWindowCount: number; aptCutoff: number; aptWindow: number;
  rctPassed: boolean; aptPassed: boolean;
  /** One line per signal, written by the engine. */
  summary: string;
  readonly healthy: boolean;
}
export function assessFileHealth(path: string, maxBytes?: number, floorBitsPerByte?: number): HealthReport;
export function assessHealthOf(bytes: Bytes, maxBytes?: number, floorBitsPerByte?: number): HealthReport;

export interface LiveFeedReport {
  accepted: boolean; creditedBits: number; creditedBitsTotal: number; ready: boolean; minEntropyPerByte: number;
  longestRun: number; rctCutoff: number; rctPassed: boolean; aptPassed: boolean;
  /** Why the chunk was not credited; empty when it was. */
  reason: string;
}
export interface LiveStatus {
  chunksFed: number; chunksAccepted: number; chunksRejected: number; bytesFed: number; reseeds: number;
  creditedBitsTotal: number; creditedBitsSinceReseed: number; minCreditedBits: number; ready: boolean;
  lastMinEntropyPerByte: number; lastLongestRun: number; lastRctCutoff: number; lastReason: string;
}
/** A continuous entropy source fed by a live stream; generate() throws until the first seed is earned. */
export class LiveEntropy {
  feed(chunk: Bytes, sourceId?: number): LiveFeedReport;
  generate(n: number): Buffer;
  status(): LiveStatus;
  close(): void;
}
export interface LivePolicy { minBitsPerByte?: number; requireRct?: boolean; minCreditedBits?: number; }
export function liveEntropy(policy?: LivePolicy): LiveEntropy;

/** HMAC-DRBG (SP 800-90A). */
export class Drbg {
  generate(n: number, additional?: Bytes | null): Buffer;
  reseed(entropy: Bytes, additional?: Bytes | null): void;
  close(): void;
}
/** Fortuna-style entropy pool. */
export class Fortuna {
  addEntropy(sourceId: number, data: Bytes): void;
  generate(n: number): Buffer;
  reseed(): void;
  reseedCount(): number;
  close(): void;
}
export const Rng: {
  bytes(n: number): Buffer;
  drbg(entropy: Bytes, opts?: { nonce?: Bytes | null; personalization?: Bytes | null }): Drbg;
  fortuna(): Fortuna;
  live(policy?: LivePolicy): LiveEntropy;
};

export type MediaFormatName = 'ppmImage' | 'wavAudio' | 'crvfVideo' | 'bmpImage' | 'pngImage' | 'flacAudio' | 'aviVideo'
  | 'gifImage' | 'jpegImage' | 'mp3Audio' | 'mp4Video' | 'unknown';
/** A media format by name ('pngImage'), by wire value, or as a bare extension ('png'). */
export type MediaFormatRef = MediaFormatName | number | string;
export const MediaFormat: { [value: number]: MediaFormatName } & { [name in MediaFormatName]: number } & {
  extensions: { [name in MediaFormatName]: string };
  extensionOf(format: MediaFormatRef): string;
};
export interface FileInspection {
  parses: boolean; format: MediaFormatName; extensionMatches: boolean; width: number; height: number; fileSize: number; detail: string;
}
export interface HiddenDataReport {
  cipherbirdPayload: boolean; lsbChiSquare: number; lsbEmbeddingLikelihood: number; samplesAnalysed: number; note: string;
}
export function stegoEmbed(coverPath: string, payload: Bytes, outputPath: string): void;
export function stegoExtract(stegoPath: string): Buffer;
export function stegoCapacity(coverPath: string): number;
export const StegoAdvanced: {
  embedKeyed(coverPath: string, payload: Bytes, outputPath: string, key: Bytes): void;
  extractKeyed(stegoPath: string, key: Bytes): Buffer;
  embedEncrypted(coverPath: string, plaintext: Bytes, outputPath: string, masterKey: Bytes): void;
  extractDecrypt(stegoPath: string, masterKey: Bytes): Buffer;
  inspect(path: string): FileInspection;
  detectHidden(path: string): HiddenDataReport;
  contentDigest(path: string): Buffer;
};
export function stegoEmbedBytes(cover: Bytes, format: MediaFormatRef, payload: Bytes): Buffer;
export function stegoExtractBytes(stego: Bytes, format: MediaFormatRef): Buffer;
export function stegoCapacityOf(cover: Bytes, format: MediaFormatRef): number;
export function stegoInspectBytes(bytes: Bytes, format: MediaFormatRef): FileInspection;
export function stegoDetectHiddenBytes(bytes: Bytes, format: MediaFormatRef): HiddenDataReport;
export function stegoContentDigestOf(bytes: Bytes, format: MediaFormatRef): Buffer;
export function stegoEmbedKeyedBytes(cover: Bytes, format: MediaFormatRef, payload: Bytes, key: Bytes): Buffer;
export function stegoExtractKeyedBytes(stego: Bytes, format: MediaFormatRef, key: Bytes): Buffer;
export function stegoEmbedEncryptedBytes(cover: Bytes, format: MediaFormatRef, plaintext: Bytes, masterKey: Bytes): Buffer;
export function stegoExtractDecryptBytes(stego: Bytes, format: MediaFormatRef, masterKey: Bytes): Buffer;

export const FecScheme: { readonly none: 0; readonly repetition3: 1; readonly repetition5: 2; readonly hamming74: 3 };
export const Composed: {
  fecEncode(data: Bytes, scheme: number): Buffer;
  fecDecode(data: Bytes, scheme: number, originalLength: number): Buffer;
  physicalSeal(o: { keyMediaPath: string; plaintext: Bytes; coverPath: string; outputPath: string; aad?: Bytes | null }): void;
  physicalOpen(o: { keyMediaPath: string; stegoPath: string; aad?: Bytes | null }): Buffer;
  imageFactorSeal(o: { oprfSecretSeed: Bytes; referenceImagePath: string; plaintext: Bytes; coverPath: string; outputPath: string; aad?: Bytes | null }): void;
  imageFactorOpen(o: { oprfSecretSeed: Bytes; referenceImagePath: string; stegoPath: string; aad?: Bytes | null }): Buffer;
  hpkeStegoSeal(o: { recipientPublic: Bytes; plaintext: Bytes; coverPath: string; outputPath: string; aad?: Bytes | null; info?: Bytes | null }): Buffer;
  hpkeStegoOpen(o: { recipientSecret: Bytes; enc: Bytes; stegoPath: string; aad?: Bytes | null; info?: Bytes | null }): Buffer;
};
export function physicalSealBytes(o: { keyMedia: Bytes; keyMediaFormat: MediaFormatRef; plaintext: Bytes; cover: Bytes; coverFormat: MediaFormatRef; aad?: Bytes | null }): Buffer;
export function physicalOpenBytes(o: { keyMedia: Bytes; keyMediaFormat: MediaFormatRef; stego: Bytes; stegoFormat: MediaFormatRef; aad?: Bytes | null }): Buffer;
export function hpkeStegoSealBytes(o: { recipientPublic: Bytes; plaintext: Bytes; cover: Bytes; coverFormat: MediaFormatRef; aad?: Bytes | null; info?: Bytes | null }): { enc: Buffer; carrier: Buffer };
export function hpkeStegoOpenBytes(o: { recipientSecret: Bytes; enc: Bytes; stego: Bytes; stegoFormat: MediaFormatRef; aad?: Bytes | null; info?: Bytes | null }): Buffer;
export function imageFactorSealBytes(o: { oprfSecretSeed: Bytes; referenceImage: Bytes; referenceFormat: MediaFormatRef; plaintext: Bytes; cover: Bytes; coverFormat: MediaFormatRef; aad?: Bytes | null }): Buffer;
export function imageFactorOpenBytes(o: { oprfSecretSeed: Bytes; referenceImage: Bytes; referenceFormat: MediaFormatRef; stego: Bytes; stegoFormat: MediaFormatRef; aad?: Bytes | null }): Buffer;
/** Scratch files in a private temporary directory, wiped on dispose(). */
export class MediaScratch {
  put(extension: string, bytes: Bytes): string;
  reserve(extension: string): string;
  take(path: string): Buffer;
  dispose(): void;
}

export function suiteSealPq(pt: Bytes, recipientKemPublic: Bytes, aad?: Bytes | null): Buffer;
export function suiteSealPqSntrup(pt: Bytes, recipientKemPublic: Bytes, aad?: Bytes | null): Buffer;
export function suiteOpenPq(env: Bytes, recipientKemSecret: Bytes, aad?: Bytes | null): Buffer;
export function suiteSealSignedPq(pt: Bytes, recipientKemPublic: Bytes, signerSigSecret: Bytes, aad?: Bytes | null): Buffer;
export function suiteSealSignedPqSntrup(pt: Bytes, recipientKemPublic: Bytes, signerSigSecret: Bytes, aad?: Bytes | null): Buffer;
export function suiteOpenSignedPq(env: Bytes, recipientKemSecret: Bytes, signerSigPublic: Bytes, aad?: Bytes | null): Buffer;
export function suiteSealWithFile(pt: Bytes, path: string, aad?: Bytes | null): Buffer;
export function suiteOpenWithFile(env: Bytes, path: string, aad?: Bytes | null): Buffer;
export function suiteSealWithKeyringDevice(pt: Bytes, kr: Handle, factorKey: Bytes, aad?: Bytes | null): Buffer;
export function suiteOpenWithKeyringDevice(env: Bytes, kr: Handle, factorKey: Bytes, aad?: Bytes | null): Buffer;
export function suiteSealWithKeyringPassphrase(pt: Bytes, kr: Handle, passphrase: Bytes, aad?: Bytes | null): Buffer;
export function suiteOpenWithKeyringPassphrase(env: Bytes, kr: Handle, passphrase: Bytes, aad?: Bytes | null): Buffer;
export function suiteEvmAddress(secp256k1PublicKey: Bytes): Buffer;
export function suiteSealThreshold(pt: Bytes, n: number, k: number, aad?: Bytes | null): { envelope: Buffer; shares: Buffer[] };
export function suiteOpenThreshold(env: Bytes, shares: Bytes[], aad?: Bytes | null): Buffer;
export const Suite2Id: { readonly xWingSig: 0x11; readonly hybridSig: 0x12 };
/** Suite v2: the signature binds recipient, KEM ciphertext and AAD. Keys: an X-Wing recipient and a hybridSigKeygen signer. */
export function suite2Seal(pt: Bytes, recipientKemPublic: Bytes, signerSigSecret: Bytes, aad?: Bytes | null, suite?: number): Buffer;
export function suite2Open(env: Bytes, recipientKemSecret: Bytes, recipientKemPublic: Bytes, signerSigPublic: Bytes, aad?: Bytes | null): Buffer;
export function suite2SuiteOf(env: Bytes): number;

export const SealedTier: { readonly Flagship: 0; readonly Fortress: 1 };
export class SealedStreamSealer {
  preamble(): Buffer;
  push(chunk: Bytes): Buffer;
  finalize(last?: Bytes | null): { ciphertext: Buffer; trailer: Buffer };
  close(): void;
}
export class SealedStreamOpener {
  pull(ct: Bytes): { plaintext: Buffer; final: boolean };
  finalize(trailer: Bytes): true;
  close(): void;
}
/** A party's recipient (KEM) and sender (signature) key pairs for Flagship or Fortress sealed messaging. */
export class Identity {
  constructor(tier: number, recipientPublic: Buffer | null, recipientSecret: Buffer | null, senderPublic: Buffer | null, senderSecret: Buffer | null);
  static generate(tier?: number): Identity;
  tier: number;
  recipientPublic: Buffer; recipientSecret: Buffer; senderPublic: Buffer; senderSecret: Buffer;
  seal(plaintext: Bytes, recipientPublic: Bytes, opts?: SealedOptions | null): Buffer;
  open(envelope: Bytes, senderPublic: Bytes, opts?: SealedOptions | null): Buffer;
  newStreamSealer(recipientPublic: Bytes, opts?: SealedOptions | null): SealedStreamSealer;
  newStreamOpener(preamble: Bytes, senderPublic: Bytes, opts?: SealedOptions | null): SealedStreamOpener;
}
export function sealedInspect(envelope: Bytes): SealedInfo;
export function sealedAddressedTo(envelope: Bytes, recipientPublic: Bytes): boolean;

/** The hybrid-KEM double ratchet (Session v1). */
export class Session {
  static generatePrekey(): KeyPair;
  static initiate(responderPrekeyPublic: Bytes): Session;
  static accept(handshake: Bytes, prekeyPublic: Bytes, prekeySecret: Bytes): Session;
  handshake(): Buffer;
  encrypt(plaintext: Bytes, aad?: Bytes | null): Buffer;
  decrypt(message: Bytes, aad?: Bytes | null): Buffer;
  close(): void;
}
export function generateSessionPrekey(): KeyPair;
export function initiateSession(responderPrekeyPublic: Bytes): Session;
export function acceptSession(handshake: Bytes, prekeyPublic: Bytes, prekeySecret: Bytes): Session;
/** Session v2: the X-Wing ratchet behind an authenticated handshake; identities are hybridSigKeygen pairs. */
export class Session2 {
  static generatePrekey(responderSigSecret: Bytes): KeyPair;
  static verifyPrekey(bundle: Bytes, responderSigPublic: Bytes): Buffer;
  static claimedInitiator(handshake: Bytes): Buffer;
  static initiate(bundle: Bytes, responderSigPublic: Bytes, initiatorSigPublic: Bytes, initiatorSigSecret: Bytes): Session2;
  static accept(handshake: Bytes, bundle: Bytes, prekeySecret: Bytes, responderSigPublic: Bytes, responderSigSecret: Bytes, expectedInitiatorSigPublic: Bytes): Session2;
  handshake(): Buffer;
  encrypt(plaintext: Bytes, aad?: Bytes | null): Buffer;
  decrypt(message: Bytes, aad?: Bytes | null): Buffer;
  close(): void;
}
export function generateSession2Prekey(responderSigSecret: Bytes): KeyPair;
export function verifySession2Prekey(bundle: Bytes, responderSigPublic: Bytes): Buffer;
export function claimedSession2Initiator(handshake: Bytes): Buffer;
export function initiateSession2(bundle: Bytes, responderSigPublic: Bytes, initiatorSigPublic: Bytes, initiatorSigSecret: Bytes): Session2;
export function acceptSession2(handshake: Bytes, bundle: Bytes, prekeySecret: Bytes, responderSigPublic: Bytes, responderSigSecret: Bytes, expectedInitiatorSigPublic: Bytes): Session2;

export interface FrostNonces { hiding: Buffer; binding: Buffer; }
export interface FrostCommitment { identifier: number; hiding: Buffer; binding: Buffer; }
export const Frost: {
  keygen(n: number, t: number): { groupPublicKey: Buffer; secretShares: Buffer[]; publicShares: Buffer[] };
  commit(shareSecret: Bytes, identifier: number): { nonces: FrostNonces; commitment: FrostCommitment };
  commitWithNonces(identifier: number, hiding: Bytes, binding: Bytes): { nonces: FrostNonces; commitment: FrostCommitment };
  sign(identifier: number, shareSecret: Bytes, groupPublicKey: Bytes, nonces: FrostNonces, msg: Bytes, commitments: FrostCommitment[]): Buffer;
  aggregate(groupPublicKey: Bytes, msg: Bytes, commitments: FrostCommitment[], sigShares: Bytes[]): Buffer;
  verify(msg: Bytes, sig: Bytes, groupPublicKey: Bytes): boolean;
  verifyShare(identifier: number, publicShare: Bytes, sigShare: Bytes, commitment: FrostCommitment, groupPublicKey: Bytes, msg: Bytes, commitments: FrostCommitment[]): boolean;
};

export class HpkeContext {
  seal(plaintext: Bytes, aad?: Bytes | null): Buffer;
  open(ciphertext: Bytes, aad?: Bytes | null): Buffer;
  export(exporterContext: Bytes | null, length: number): Buffer;
  close(): void;
}
export const HpkeKem: { readonly DhkemX25519: 0x0020; readonly MlKem768: 0x0041; readonly XWing: 0x647A };
export interface HpkeSenderOptions { psk?: Bytes | null; pskId?: Bytes | null; skS?: Bytes | null; }
export interface HpkeReceiverOptions { psk?: Bytes | null; pskId?: Bytes | null; pkS?: Bytes | null; }
export const Hpke: {
  Kdf: { readonly Sha256: 1; readonly Sha512: 3 };
  Aead: { readonly Aes128Gcm: 1; readonly Aes256Gcm: 2; readonly ChaCha20Poly1305: 3; readonly ExportOnly: 0xFFFF };
  Mode: { readonly Base: 0; readonly Psk: 1; readonly Auth: 2; readonly AuthPsk: 3 };
  Kem: typeof HpkeKem;
  keygen(): KeyPair;
  deriveKeyPair(ikm: Bytes): KeyPair;
  setupS(kdf: number, aead: number, mode: number, recipientPublic: Bytes, info: Bytes, opts?: HpkeSenderOptions): { enc: Buffer; context: HpkeContext };
  setupR(kdf: number, aead: number, mode: number, enc: Bytes, recipientSecret: Bytes, info: Bytes, opts?: HpkeReceiverOptions): HpkeContext;
  sealBase(kdf: number, aead: number, recipientPublic: Bytes, info: Bytes, plaintext: Bytes, aad?: Bytes | null): { enc: Buffer; ct: Buffer };
  openBase(kdf: number, aead: number, enc: Bytes, recipientSecret: Bytes, info: Bytes, ciphertext: Bytes, aad?: Bytes | null): Buffer;
  kemAvailable(kem: number): boolean;
  keygenKem(kem: number): KeyPair;
  deriveKeyPairKem(kem: number, ikm: Bytes): KeyPair;
  setupSKem(kem: number, kdf: number, aead: number, mode: number, recipientPublic: Bytes, info: Bytes, opts?: HpkeSenderOptions): { enc: Buffer; context: HpkeContext };
  setupRKem(kem: number, kdf: number, aead: number, mode: number, enc: Bytes, recipientSecret: Bytes, info: Bytes, opts?: HpkeReceiverOptions): HpkeContext;
};
export function hpkeKemAvailable(kem: number): boolean;
export function hpkeKeygenKem(kem: number): KeyPair;
export function hpkeDeriveKeypairKem(kem: number, ikm: Bytes): KeyPair;
export function hpkeSetupSKem(kem: number, kdf: number, aead: number, mode: number, recipientPublic: Bytes, info: Bytes, opts?: HpkeSenderOptions): { enc: Buffer; context: HpkeContext };
export function hpkeSetupRKem(kem: number, kdf: number, aead: number, mode: number, enc: Bytes, recipientSecret: Bytes, info: Bytes, opts?: HpkeReceiverOptions): HpkeContext;

export const Ecvrf: {
  keygen(): KeyPair;
  publicKey(secretKey: Bytes): Buffer;
  prove(secretKey: Bytes, alpha: Bytes): Buffer;
  proofToHash(proof: Bytes): Buffer;
  verify(publicKey: Bytes, alpha: Bytes, proof: Bytes): Buffer;
};

export const Bbs: {
  keygen(keyMaterial: Bytes, keyInfo?: Bytes | null): KeyPair;
  skToPk(secretKey: Bytes): Buffer;
  sign(secretKey: Bytes, publicKey: Bytes, header: Bytes, messages: Bytes[]): Buffer;
  verify(publicKey: Bytes, signature: Bytes, header: Bytes, messages: Bytes[]): boolean;
  proofGen(publicKey: Bytes, signature: Bytes, header: Bytes, ph: Bytes, messages: Bytes[], disclosedIndexes: number[]): Buffer;
  proofVerify(publicKey: Bytes, proof: Bytes, header: Bytes, ph: Bytes, disclosedMessages: Bytes[], disclosedIndexes: number[]): boolean;
  commitWithNym(committedMessages: Bytes[], proverNyms: Bytes[]): { commitmentWithProof: Buffer; secretProverBlind: Buffer };
  blindSignWithNym(secretKey: Bytes, publicKey: Bytes, commitmentWithProof: Bytes, header: Bytes, messages: Bytes[], signerNymEntropy: Bytes, lengthNymVector: number): Buffer;
  finalizeNymSecrets(proverNyms: Bytes[], signerNymEntropy: Bytes): Buffer;
  calculatePseudonym(contextId: Bytes, nymSecrets: Bytes[]): Buffer;
  proofGenWithPseudonym(publicKey: Bytes, signature: Bytes, header: Bytes, ph: Bytes, contextId: Bytes, signerMessages: Bytes[], committedMessages: Bytes[], secretProverBlind: Bytes, nymSecrets: Bytes[], disclosedSignerIndexes: number[], disclosedCommittedIndexes: number[]): { proof: Buffer; pseudonym: Buffer };
  proofVerifyWithPseudonym(publicKey: Bytes, proof: Bytes, header: Bytes, ph: Bytes, contextId: Bytes, pseudonym: Bytes, L: number, lengthNymVector: number, disclosedMessages: Bytes[], disclosedIndexes: number[]): boolean;
  blindCommit(committedMessages: Bytes[]): { commitmentWithProof: Buffer; secretProverBlind: Buffer };
  blindSign(secretKey: Bytes, publicKey: Bytes, commitmentWithProof: Bytes, header: Bytes, messages: Bytes[]): Buffer;
  verifyBlindSign(publicKey: Bytes, signature: Bytes, header: Bytes, messages: Bytes[], committedMessages: Bytes[], secretProverBlind: Bytes): boolean;
  hashToScalar(msg: Bytes, dst: Bytes): Buffer;
  randomScalar(): Buffer;
};

export const Oprf: {
  deriveKeyPair(seed: Bytes, info?: Bytes | null): KeyPair;
  blind(input: Bytes): { blind: Buffer; blindedElement: Buffer };
  blindWithScalar(input: Bytes, blindScalar: Bytes): { blind: Buffer; blindedElement: Buffer };
  blindEvaluate(secretKey: Bytes, blindedElement: Bytes): Buffer;
  finalize(input: Bytes, blindScalar: Bytes, evaluatedElement: Bytes): Buffer;
  evaluate(secretKey: Bytes, input: Bytes): Buffer;
};

export const Opaque: {
  registrationRequest(password: Bytes): { blind: Buffer; request: Buffer };
  registrationResponse(request: Bytes, serverPublicKey: Bytes, credentialIdentifier: Bytes, oprfSeed: Bytes): Buffer;
  finalizeRequest(password: Bytes, blind: Bytes, response: Bytes, serverIdentity?: Bytes | null, clientIdentity?: Bytes | null): { record: Buffer; exportKey: Buffer };
  clientInit(password: Bytes): { ke1: Buffer; clientState: Buffer };
  serverRespond(context: Bytes, serverPrivateKey: Bytes, serverPublicKey: Bytes, record: Bytes, credentialIdentifier: Bytes, oprfSeed: Bytes, ke1: Bytes, serverIdentity?: Bytes | null, clientIdentity?: Bytes | null): { ke2: Buffer; serverState: Buffer };
  clientFinish(clientState: Bytes, ke2: Bytes, context: Bytes, serverIdentity?: Bytes | null, clientIdentity?: Bytes | null): { ke3: Buffer; sessionKey: Buffer; exportKey: Buffer };
  serverFinish(serverState: Bytes, ke3: Bytes): Buffer;
};

/** Incremental BLAKE3; finalize(0) gives 32 bytes, larger lengths use the extendable output. */
export class Blake3Hasher {
  update(data: Bytes): void;
  finalize(outLen?: number): Buffer;
  close(): void;
}
export function blake3Hasher(key?: Bytes | null): Blake3Hasher;
/** Noise_XX_25519_ChaChaPoly_SHA256. */
export class Noise {
  writeMessage(payload?: Bytes | null): Buffer;
  readMessage(message: Bytes): Buffer;
  handshakeFinished(): boolean;
  handshakeHash(): Buffer;
  remoteStatic(): Buffer;
  split(): void;
  encrypt(plaintext: Bytes, ad?: Bytes | null): Buffer;
  decrypt(ciphertext: Bytes, ad?: Bytes | null): Buffer;
  decryptAt(nonceCounter: number | bigint, ciphertext: Bytes, ad?: Bytes | null): Buffer;
  close(): void;
}
export function noise(initiator: boolean, staticPublic: Bytes, staticSecret: Bytes, prologue?: Bytes | null): Noise;

/** The FIPS profile: everything runs inside the OpenSSL FIPS Provider when the engine was built for it; otherwise available() is false and every call throws. */
export const FipsHash: { readonly Sha256: 0; readonly Sha384: 1; readonly Sha512: 2; readonly Sha3_256: 3 };
export interface FipsStatus {
  loaded: boolean; selfTestsPassed: boolean; approvedMode: boolean;
  providerName: string; providerVersion: string; moduleDirectory: string; configFile: string;
}
export class FipsEnvelope {
  addPassphraseSlot(passphrase: Bytes, iterations?: number): void;
  addKeySlot(factor: Bytes): void;
  unlockWithPassphrase(passphrase: Bytes): Buffer;
  unlockWithKey(factor: Bytes): Buffer;
  removeSlot(index: number): void;
  readonly slotCount: number;
  serialise(): Buffer;
  close(): void;
}
export const Fips: {
  Hash: typeof FipsHash;
  available(): boolean;
  init(opts?: { moduleDir?: string | null; configFile?: string | null }): void;
  status(): FipsStatus;
  digest(hash: number, data: Bytes): Buffer;
  hmac(hash: number, key: Bytes, data: Bytes): Buffer;
  hmacVerify(hash: number, key: Bytes, data: Bytes, tag: Bytes): boolean;
  hkdf(hash: number, ikm: Bytes, outLen?: number, opts?: { salt?: Bytes | null; info?: Bytes | null }): Buffer;
  pbkdf2(hash: number, password: Bytes, salt: Bytes, opts?: { iterations?: number; outLen?: number }): Buffer;
  random(n: number): Buffer;
  aesGcmEncrypt(key: Bytes, plaintext: Bytes, aad?: Bytes | null): Buffer;
  aesGcmDecrypt(key: Bytes, wire: Bytes, aad?: Bytes | null): Buffer;
  p256Keygen(): KeyPair;
  p256Ecdh(privateKey: Bytes, peerPublic: Bytes): Buffer;
  p256Sign(privateKey: Bytes, message: Bytes): Buffer;
  p256Verify(publicKey: Bytes, message: Bytes, signature: Bytes): boolean;
  p256PublicKey(privateKey: Bytes): Buffer;
  hpkeP256Seal(recipientPublic: Bytes, plaintext: Bytes, opts?: { info?: Bytes | null; aad?: Bytes | null }): { enc: Buffer; ciphertext: Buffer };
  hpkeP256Open(enc: Bytes, recipientSecret: Bytes, recipientPublic: Bytes, ciphertext: Bytes, opts?: { info?: Bytes | null; aad?: Bytes | null }): Buffer;
  envelopeCreate(): FipsEnvelope;
  envelopeDeserialise(blob: Bytes): FipsEnvelope;
};
export const fipsAvailable: typeof Fips.available;
export const fipsInit: typeof Fips.init;
export const fipsStatus: typeof Fips.status;
export const fipsDigest: typeof Fips.digest;
export const fipsHmac: typeof Fips.hmac;
export const fipsHmacVerify: typeof Fips.hmacVerify;
export const fipsHkdf: typeof Fips.hkdf;
export const fipsPbkdf2: typeof Fips.pbkdf2;
export const fipsRandom: typeof Fips.random;
export const fipsAesGcmEncrypt: typeof Fips.aesGcmEncrypt;
export const fipsAesGcmDecrypt: typeof Fips.aesGcmDecrypt;
export const fipsP256Keygen: typeof Fips.p256Keygen;
export const fipsP256Ecdh: typeof Fips.p256Ecdh;
export const fipsP256Sign: typeof Fips.p256Sign;
export const fipsP256Verify: typeof Fips.p256Verify;
export const fipsP256PublicKey: typeof Fips.p256PublicKey;
export const fipsHpkeP256Seal: typeof Fips.hpkeP256Seal;
export const fipsHpkeP256Open: typeof Fips.hpkeP256Open;
export const fipsEnvelopeCreate: typeof Fips.envelopeCreate;
export const fipsEnvelopeDeserialise: typeof Fips.envelopeDeserialise;

/* Security profiles and composable recipes. */
export type SecurityProfileName = 'balanced' | 'high' | 'maximum';
export const SecurityProfile: {
  readonly balanced: 'balanced'; readonly high: 'high'; readonly maximum: 'maximum';
  params(profile: SecurityProfileName): {
    mlKemLevel: number; mlDsaLevel: number; slhDsaLevel: number; slhDsaHash: number; sealedTier: number; kdfPreset: number;
    argon2Ops: number; argon2Memory: number; cascade: ProtectionLayer[];
  };
};
export abstract class ProtectionLayer {
  abstract readonly id: number;
  abstract readonly wireName: string;
  abstract seal(api: typeof import('.'), key: Buffer, aad: Buffer, plaintext: Buffer): Buffer;
  abstract open(api: typeof import('.'), key: Buffer, aad: Buffer, ciphertext: Buffer): Buffer;
  static register(layer: ProtectionLayer): void;
  static readonly xchacha20Poly1305: ProtectionLayer;
  static readonly aes256Gcm: ProtectionLayer;
  static readonly committing: ProtectionLayer;
  static readonly molecular: ProtectionLayer;
}
export class XChaCha20Layer extends ProtectionLayer { readonly id: 1; readonly wireName: string; seal(api: unknown, key: Buffer, aad: Buffer, plaintext: Buffer): Buffer; open(api: unknown, key: Buffer, aad: Buffer, ciphertext: Buffer): Buffer; }
export class Aes256GcmLayer extends ProtectionLayer { readonly id: 2; readonly wireName: string; seal(api: unknown, key: Buffer, aad: Buffer, plaintext: Buffer): Buffer; open(api: unknown, key: Buffer, aad: Buffer, ciphertext: Buffer): Buffer; }
export class CommittingLayer extends ProtectionLayer { readonly id: 3; readonly wireName: string; seal(api: unknown, key: Buffer, aad: Buffer, plaintext: Buffer): Buffer; open(api: unknown, key: Buffer, aad: Buffer, ciphertext: Buffer): Buffer; }
export class MolecularLayer extends ProtectionLayer { readonly id: 4; readonly wireName: string; seal(api: unknown, key: Buffer, aad: Buffer, plaintext: Buffer): Buffer; open(api: unknown, key: Buffer, aad: Buffer, ciphertext: Buffer): Buffer; }
/** A layer that is itself a mixture of layers. */
export class CascadeLayer extends ProtectionLayer {
  constructor(o: { id: number; wireName: string; layers: ProtectionLayer[] });
  readonly id: number;
  readonly wireName: string;
  readonly layers: ProtectionLayer[];
  seal(api: unknown, key: Buffer, aad: Buffer, plaintext: Buffer): Buffer;
  open(api: unknown, key: Buffer, aad: Buffer, ciphertext: Buffer): Buffer;
}
export abstract class KeySource {
  abstract readonly id: number;
  abstract readonly label: string;
  abstract deriveRoot(api: typeof import('.'), salt: Buffer, argon2Ops: number, argon2Memory: number): Buffer;
}
export class RawKeySource extends KeySource { constructor(key: Bytes); readonly id: 0; readonly label: 'raw'; deriveRoot(): Buffer; }
export class PassphraseKeySource extends KeySource { constructor(passphrase: Bytes); readonly id: 1; readonly label: 'passphrase'; deriveRoot(api: unknown, salt: Buffer, ops: number, mem: number): Buffer; }
export class KeyFileSource extends KeySource { constructor(path: string); readonly id: 2; readonly label: 'keyFile'; deriveRoot(api: unknown): Buffer; }
/** A media buffer as the key; the same bytes always yield the same key. */
export class KeyBytesSource extends KeySource { constructor(bytes: Bytes); readonly id: 3; readonly label: 'keyBytes'; deriveRoot(api: unknown): Buffer; }
export abstract class SignatureScheme {
  abstract readonly id: number;
  abstract readonly label: string;
  abstract sign(api: typeof import('.'), message: Buffer): Buffer;
  abstract verify(api: typeof import('.'), message: Buffer, signature: Buffer): boolean;
}
export class Ed25519Signature extends SignatureScheme {
  constructor(keys?: { secretKey?: Bytes | null; publicKey?: Bytes | null });
  readonly id: 1; readonly label: 'ed25519';
  sign(api: unknown, message: Buffer): Buffer; verify(api: unknown, message: Buffer, signature: Buffer): boolean;
}
export class HybridSignature extends SignatureScheme {
  constructor(keys?: { secretKey?: Bytes | null; publicKey?: Bytes | null });
  readonly id: 2; readonly label: 'hybrid';
  sign(api: unknown, message: Buffer): Buffer; verify(api: unknown, message: Buffer, signature: Buffer): boolean;
}
export const SignatureAlgorithm: { readonly none: 0; readonly ed25519: 1; readonly hybrid: 2 };
/** A composable protection pipeline whose envelope opens in every CipherBird binding. */
export class Recipe {
  constructor(api: unknown, profile?: SecurityProfileName);
  profile: SecurityProfileName;
  withKeySource(source: KeySource): this;
  withPassphrase(passphrase: Bytes): this;
  withKey(key: Bytes): this;
  withKeyFile(path: string): this;
  withLayers(layers: ProtectionLayer[]): this;
  addLayer(layer: ProtectionLayer): this;
  argon2Cost(o?: { ops?: number; memoryBytes?: number }): this;
  signedWith(scheme: SignatureScheme): this;
  verifiedWith(scheme: SignatureScheme): this;
  signedBy(secretKey: Bytes, algorithm?: number): this;
  verifiedBy(publicKey: Bytes): this;
  withFec(scheme: number): this;
  describe(): string;
  seal(plaintext: Bytes): Buffer;
  open(envelope: Bytes): Buffer;
  sealIntoCarrier(plaintext: Bytes, o: { coverPath: string; outputPath: string }): void;
  openFromCarrier(stegoPath: string): Buffer;
}
export function recipe(profile?: SecurityProfileName): Recipe;
export function maximumSecurity(): Recipe;

/* Easy mode. */
export type SignatureAlgorithmRef = 'ed25519' | 'hybrid' | 1 | 2;
/** A 32-byte symmetric key with the safe choices built in: committing AEAD, Argon2id passphrases, HKDF sub-keys. */
export class SymmetricKey {
  static generate(): SymmetricKey;
  static fromBytes(key: Bytes): SymmetricKey;
  static fromHex(hex: string): SymmetricKey;
  static fromBase64(b64: string): SymmetricKey;
  static fromPassphrase(passphrase: Bytes, opts: { salt: Bytes; profile?: SecurityProfileName; ops?: number; memoryBytes?: number }): SymmetricKey;
  static fromPassphraseBytes(passphrase: Bytes, opts: { salt: Bytes; profile?: SecurityProfileName; ops?: number; memoryBytes?: number }): SymmetricKey;
  readonly bytes: Buffer;
  readonly hex: string;
  readonly base64: string;
  readonly asKeySource: KeySource;
  readonly isDestroyed: boolean;
  derive(purpose: string): SymmetricKey;
  encrypt(plaintext: Bytes, opts?: { aad?: Bytes | null }): Buffer;
  decrypt(ciphertext: Bytes, opts?: { aad?: Bytes | null }): Buffer;
  encryptText(text: string, opts?: { aad?: string | null }): string;
  decryptText(b64: string, opts?: { aad?: string | null }): string;
  destroy(): void;
}
export class VerifyKey {
  static fromBytes(publicKey: Bytes, opts?: { algorithm?: SignatureAlgorithmRef }): VerifyKey;
  static fromHex(hex: string, opts?: { algorithm?: SignatureAlgorithmRef }): VerifyKey;
  readonly publicKey: Buffer;
  readonly algorithm: number;
  readonly scheme: SignatureScheme;
  verify(message: Bytes, signature: Bytes): boolean;
  verifyText(message: string, signatureBase64: string): boolean;
}
export class SigningKey {
  static generate(opts?: { algorithm?: SignatureAlgorithmRef }): SigningKey;
  static fromBytes(o: { secretKey: Bytes; publicKey: Bytes; algorithm?: SignatureAlgorithmRef }): SigningKey;
  readonly publicKey: Buffer;
  readonly secretKey: Buffer;
  readonly algorithm: number;
  readonly verifyKey: VerifyKey;
  readonly scheme: SignatureScheme;
  sign(message: Bytes): Buffer;
  signText(message: string): string;
  verify(message: Bytes, signature: Bytes): boolean;
  destroy(): void;
}
/** The X25519 + ML-KEM-768 hybrid key pair with one-call public-key encryption. */
export class KemKeyPair {
  static generate(): KemKeyPair;
  static fromBytes(o: { publicKey: Bytes; secretKey: Bytes }): KemKeyPair;
  static encapsulate(recipientPublicKey: Bytes): { ciphertext: Buffer; key: SymmetricKey };
  static encryptFor(recipientPublicKey: Bytes, plaintext: Bytes, opts?: { aad?: Bytes | null }): Buffer;
  static encryptTextFor(recipientPublicKey: Bytes, text: string, opts?: { aad?: string | null }): string;
  readonly publicKey: Buffer;
  readonly secretKey: Buffer;
  decapsulate(ciphertext: Bytes): SymmetricKey;
  decrypt(blob: Bytes, opts?: { aad?: Bytes | null }): Buffer;
  decryptText(b64: string, opts?: { aad?: string | null }): string;
  destroy(): void;
}
export const easy: {
  symmetricKey(): SymmetricKey;
  symmetricKeyFromPassphrase(passphrase: Bytes, opts: { salt: Bytes; profile?: SecurityProfileName; ops?: number; memoryBytes?: number }): SymmetricKey;
  symmetricKeyFromPassphraseBytes(passphrase: Bytes, opts: { salt: Bytes; profile?: SecurityProfileName; ops?: number; memoryBytes?: number }): SymmetricKey;
  signingKey(opts?: { algorithm?: SignatureAlgorithmRef }): SigningKey;
  kemKeyPair(): KemKeyPair;
  identity(tier?: number): Identity;
  randomBytes(n: number): Buffer;
  randomHex(n: number): string;
  token(bytes?: number): string;
  hashPassword(password: Bytes, opts?: { profile?: SecurityProfileName }): string;
  hashPasswordBytes(password: Bytes, opts?: { profile?: SecurityProfileName }): string;
  verifyPassword(password: Bytes, phc: string): boolean;
  verifyPasswordBytes(password: Bytes, phc: string): boolean;
  sha256Hex(text: string): string;
  symmetricKeyFromPassphraseAsync(passphrase: Bytes, opts: { salt: Bytes; profile?: SecurityProfileName; ops?: number; memoryBytes?: number }): Promise<SymmetricKey>;
  hashPasswordAsync(password: Bytes, opts?: { profile?: SecurityProfileName }): Promise<string>;
  verifyPasswordAsync(password: Bytes, phc: string): Promise<boolean>;
};
export function toHex(b: Bytes): string;
export function fromHex(s: string): Buffer;
export function toBase64(b: Bytes): string;
export function fromBase64(s: string): Buffer;
export function toBase64Url(b: Bytes): string;
export function fromBase64Url(s: string): Buffer;
export function utf8Bytes(s: string): Buffer;
export function utf8Text(b: Bytes): string;
export function constantTimeEquals(a: Bytes, b: Bytes): boolean;

/* Off the main thread. */
export type Awaited1<F> = F extends (...a: infer A) => infer R ? (...a: A) => Promise<R> : never;
/** cipherbird.async.<method>(...args) runs any data-in, data-out method on one worker thread. */
export const async: {
  run(method: string, ...args: unknown[]): Promise<unknown>;
  close(): Promise<number>;
  readonly alive: boolean;
} & { [method: string]: (...args: unknown[]) => Promise<any> };
export function runAsync(method: string, ...args: unknown[]): Promise<unknown>;
export const mlDsaKeygenAsync: Awaited1<typeof mlDsaKeygen>;
export const slhDsaKeygenAsync: Awaited1<typeof slhDsaKeygen>;
export const hybridSigSignAsync: Awaited1<typeof hybridSigSign>;
export const keyFromBytesAsync: Awaited1<typeof keyFromBytes>;
export const mlDsaSignAsync: Awaited1<typeof mlDsaSign>;
export const slhDsaSignAsync: Awaited1<typeof slhDsaSign>;
export const stegoEmbedBytesAsync: Awaited1<typeof stegoEmbedBytes>;
export const stegoEmbedEncryptedBytesAsync: Awaited1<typeof stegoEmbedEncryptedBytes>;
export const stegoExtractBytesAsync: Awaited1<typeof stegoExtractBytes>;
export const stegoExtractDecryptBytesAsync: Awaited1<typeof stegoExtractDecryptBytes>;
export const suite2OpenAsync: Awaited1<typeof suite2Open>;
export const suite2SealAsync: Awaited1<typeof suite2Seal>;
export const argon2idDeriveAsync: Awaited1<typeof argon2idDerive>;
export const argon2idHashStrAsync: Awaited1<typeof argon2idHashStr>;
export const argon2idVerifyStrAsync: Awaited1<typeof argon2idVerifyStr>;

/* Domain namespaces, the same grouping as the Dart packages. */
export const hash: {
  blake3Hasher(o?: { key?: Bytes | null }): Blake3Hasher;
  blake2b(msg: Bytes, key?: Bytes | null): Buffer;
  sha256(msg: Bytes): Buffer; sha512(msg: Bytes): Buffer;
  hmacSha512(msg: Bytes, key: Bytes): Buffer; hmacSha512Verify(msg: Bytes, mac: Bytes, key: Bytes): boolean;
  argon2idHashStr(password: Bytes, o?: { ops?: number; mem?: number }): string;
  argon2idVerifyStr(password: Bytes, phc: string): boolean;
  argon2idDerive(password: Bytes, salt: Bytes, o?: { keyLen?: number; ops?: number; mem?: number }): Buffer;
  argon2idHashStrBytes(password: Bytes, o?: { ops?: number; mem?: number }): string;
  argon2idVerifyStrBytes(password: Bytes, phc: string): boolean;
  argon2idDeriveBytes(password: Bytes, salt: Bytes, o?: { keyLen?: number; ops?: number; mem?: number }): Buffer;
  blake3(msg: Bytes, o?: { outLen?: number }): Buffer;
  blake3Keyed(msg: Bytes, key: Bytes, o?: { outLen?: number }): Buffer;
  blake3DeriveKey(context: string, ikm: Bytes, o?: { outLen?: number }): Buffer;
  hmacSha256(msg: Bytes, key: Bytes): Buffer; hmacSha256Verify(msg: Bytes, mac: Bytes, key: Bytes): boolean;
  hkdfExtract(ikm: Bytes, o?: { salt?: Bytes | null }): Buffer;
  hkdfExpand(prk: Bytes, o?: { info?: Bytes | null; outLen?: number }): Buffer;
  hkdfDerive(ikm: Bytes, o?: { salt?: Bytes | null; info?: Bytes | null; outLen?: number }): Buffer;
  keccak256(msg: Bytes): Buffer; ripemd160(msg: Bytes): Buffer; secureEqual(a: Bytes, b: Bytes): boolean;
};
export const aead: {
  symKeygen(): Buffer;
  xchacha20Encrypt(pt: Bytes, key: Bytes, aad?: Bytes | null): Buffer; xchacha20Decrypt(ct: Bytes, key: Bytes, aad?: Bytes | null): Buffer;
  aes256gcmEncrypt(pt: Bytes, key: Bytes, aad?: Bytes | null): Buffer; aes256gcmDecrypt(ct: Bytes, key: Bytes, aad?: Bytes | null): Buffer;
  aes256gcmAvailable(): boolean;
  streamEncrypt(key: Bytes, chunks: Bytes[]): { header: Buffer; chunks: Buffer[] };
  streamDecrypt(key: Bytes, header: Bytes, chunks: Bytes[]): Buffer[];
  committingEncrypt(pt: Bytes, key: Bytes, aad?: Bytes | null): Buffer; committingDecrypt(ct: Bytes, key: Bytes, aad?: Bytes | null): Buffer;
};
export const asym: {
  ed25519Keygen(): KeyPair; ed25519KeygenFromSeed(seed: Bytes): KeyPair;
  ed25519Sign(msg: Bytes, sk: Bytes): Buffer; ed25519Verify(msg: Bytes, sig: Bytes, pk: Bytes): boolean;
  x25519Keygen(): KeyPair; x25519SharedSecret(sk: Bytes, pk: Bytes): Buffer;
  boxKeygen(): KeyPair; boxEncrypt(pt: Bytes, recipientPub: Bytes, senderSec: Bytes): Buffer; boxDecrypt(ct: Bytes, senderPub: Bytes, recipientSec: Bytes): Buffer;
  sealedboxEncrypt(pt: Bytes, recipientPub: Bytes): Buffer; sealedboxDecrypt(ct: Bytes, recipientPub: Bytes, recipientSec: Bytes): Buffer;
};
export const bls: {
  keygen(): KeyPair; sign(msg: Bytes, sk: Bytes): Buffer; verify(msg: Bytes, sig: Bytes, pk: Bytes): boolean;
  keygenFromIkm(ikm: Bytes): KeyPair; aggregate(sigs: Bytes[]): Buffer; aggregateVerify(msgs: Bytes[], pks: Bytes[], agg: Bytes): boolean;
};
export const vault: {
  vaultCreate(masterKey: Bytes, o?: { kdfPreset?: number }): Handle;
  vaultFromEntropy(entropy: Handle, o?: { kdf?: number }): Handle;
  vaultSeal(v: Handle, pt: Bytes, aad?: string): Packet;
  vaultSealBoosted(v: Handle, pt: Bytes, aad: string, boost: Handle): Packet;
  vaultOpen(v: Handle, pkt: Packet, aad?: string): Buffer;
  vaultOpenBoosted(v: Handle, pkt: Packet, aad: string, boost: Handle): Buffer;
  vaultPublicKey(v: Handle): Buffer;
  packetSerialise(pkt: Packet): Buffer; packetDeserialise(data: Bytes): Packet;
  vaultFree(v: Handle): void;
  asymBundleGenerate(): AsymBundle;
  asymVaultSeal(sender: AsymBundle, recipientBoxPub: Bytes, pt: Bytes, aad?: string): Packet;
  asymVaultOpen(pkt: Packet, recipient: AsymBundle, senderSignPub: Bytes, aad?: string): Buffer;
  molecularSeal(pt: Bytes, passphrase: Bytes, o?: { aad?: Bytes | null; ops?: number; mem?: number }): Buffer;
  molecularOpen(env: Bytes, passphrase: Bytes, o?: { aad?: Bytes | null }): Buffer;
  molecularSealWithKey(pt: Bytes, masterKey: Bytes, o?: { aad?: Bytes | null }): Buffer;
  molecularOpenWithKey(env: Bytes, masterKey: Bytes, o?: { aad?: Bytes | null }): Buffer;
};
export const keyring: {
  create(): Handle;
  addDeviceSlot(kr: Handle, factor: Bytes): boolean;
  addPassphraseSlot(kr: Handle, passphrase: Bytes, kdf?: number): boolean;
  addPassphraseSlotBytes(kr: Handle, passphrase: Bytes, kdf?: number): boolean;
  slotCount(kr: Handle): number; serialise(kr: Handle): Buffer; deserialise(blob: Bytes): Handle;
  unlockWithDevice(kr: Handle, factor: Bytes): Buffer;
  unlockWithPassphrase(kr: Handle, passphrase: Bytes): Buffer;
  unlockWithPassphraseBytes(kr: Handle, passphrase: Bytes): Buffer;
  free(kr: Handle): void; removeSlot(kr: Handle, index: number): boolean;
  addHardwareSlot(kr: Handle, keyId: Bytes): Buffer;
  setHardwareBlob(kr: Handle, index: number, blob: Bytes): boolean;
  slotType(kr: Handle, index: number): number;
  hardwareSlot(kr: Handle, index: number): { keyId: Buffer; blob: Buffer };
  unlockWithHardware(kr: Handle, index: number, factor: Bytes): Buffer;
};
export const entropy: {
  fromFile(p: string): Handle; fromFileDeterministic(p: string): Handle;
  fromFiles(paths: string[]): Handle; fromFilesDeterministic(paths: string[]): Handle;
  fromFileWithPolicy(p: string, policy?: EntropyPolicy): Handle;
  fromBytes(bytes: Bytes, policy?: EntropyPolicy & { extension?: string }): Handle;
  deriveAll(h: Handle): DerivedKeys; symmetricKey(h: Handle): Buffer; raw(h: Handle): Buffer; boost(h: Handle): Buffer;
  info(h: Handle): EntropyInfo; asymBundle(h: Handle): AsymBundle; refresh(h: Handle): void; free(h: Handle): void;
  keyFromFile(p: string): Buffer; keyFromBytes(bytes: Bytes): Buffer;
  sealFromFile(p: string, plaintext: string, aad?: string): Packet; openFromFile(p: string, pkt: Packet, aad?: string): Buffer;
  sealWithBytes(bytes: Bytes, plaintext: string, aad?: string): Packet; openWithBytes(bytes: Bytes, pkt: Packet, aad?: string): Buffer;
  assessFileHealth(p: string, o?: { maxBytes?: number; floorBitsPerByte?: number }): HealthReport;
  assessHealthOf(bytes: Bytes, o?: { maxBytes?: number; floorBitsPerByte?: number }): HealthReport;
};
export const stego: {
  embed(coverPath: string, payload: Bytes, outputPath: string): void;
  extract(stegoPath: string): Buffer;
  capacity(coverPath: string): number;
  embedKeyed(coverPath: string, payload: Bytes, outputPath: string, key: Bytes): void;
  extractKeyed(stegoPath: string, key: Bytes): Buffer;
  embedEncrypted(coverPath: string, plaintext: Bytes, outputPath: string, masterKey: Bytes): void;
  extractDecrypt(stegoPath: string, masterKey: Bytes): Buffer;
  inspect(p: string): FileInspection; detectHidden(p: string): HiddenDataReport; contentDigest(p: string): Buffer;
  embedBytes(cover: Bytes, format: MediaFormatRef, payload: Bytes): Buffer;
  extractBytes(stego: Bytes, format: MediaFormatRef): Buffer;
  capacityOf(cover: Bytes, format: MediaFormatRef): number;
  inspectBytes(bytes: Bytes, format: MediaFormatRef): FileInspection;
  detectHiddenBytes(bytes: Bytes, format: MediaFormatRef): HiddenDataReport;
  contentDigestOf(bytes: Bytes, format: MediaFormatRef): Buffer;
  embedKeyedBytes(cover: Bytes, format: MediaFormatRef, payload: Bytes, key: Bytes): Buffer;
  extractKeyedBytes(stego: Bytes, format: MediaFormatRef, key: Bytes): Buffer;
  embedEncryptedBytes(cover: Bytes, format: MediaFormatRef, plaintext: Bytes, masterKey: Bytes): Buffer;
  extractDecryptBytes(stego: Bytes, format: MediaFormatRef, masterKey: Bytes): Buffer;
};
export const composed: typeof Composed & {
  physicalSealBytes: typeof physicalSealBytes; physicalOpenBytes: typeof physicalOpenBytes;
  imageFactorSealBytes: typeof imageFactorSealBytes; imageFactorOpenBytes: typeof imageFactorOpenBytes;
  hpkeStegoSealBytes: typeof hpkeStegoSealBytes; hpkeStegoOpenBytes: typeof hpkeStegoOpenBytes;
};
export const chain: {
  keccak256(msg: Bytes): Buffer; ripemd160(msg: Bytes): Buffer;
  secp256k1Keygen(): KeyPair; secp256k1Pubkey(sk: Bytes, o?: { compressed?: boolean }): Buffer;
  secp256k1Sign(digest: Bytes, sk: Bytes): Buffer; secp256k1Verify(digest: Bytes, sig: Bytes, pk: Bytes): boolean;
  secp256k1Recover(digest: Bytes, sig65: Bytes): Buffer; evmAddress(pk: Bytes): Buffer;
};
export const suite: {
  sealPq(pt: Bytes, pk: Bytes, o?: { aad?: Bytes | null }): Buffer;
  sealPqSntrup(pt: Bytes, pk: Bytes, o?: { aad?: Bytes | null }): Buffer;
  openPq(env: Bytes, sk: Bytes, o?: { aad?: Bytes | null }): Buffer;
  sealSignedPq(pt: Bytes, pk: Bytes, signerSk: Bytes, o?: { aad?: Bytes | null }): Buffer;
  sealSignedPqSntrup(pt: Bytes, pk: Bytes, signerSk: Bytes, o?: { aad?: Bytes | null }): Buffer;
  openSignedPq(env: Bytes, sk: Bytes, signerPk: Bytes, o?: { aad?: Bytes | null }): Buffer;
  sealWithFile(pt: Bytes, p: string, o?: { aad?: Bytes | null }): Buffer;
  openWithFile(env: Bytes, p: string, o?: { aad?: Bytes | null }): Buffer;
  sealWithKeyringDevice(pt: Bytes, kr: Handle, factor: Bytes, o?: { aad?: Bytes | null }): Buffer;
  openWithKeyringDevice(env: Bytes, kr: Handle, factor: Bytes, o?: { aad?: Bytes | null }): Buffer;
  sealWithKeyringPassphrase(pt: Bytes, kr: Handle, pw: Bytes, o?: { aad?: Bytes | null }): Buffer;
  openWithKeyringPassphrase(env: Bytes, kr: Handle, pw: Bytes, o?: { aad?: Bytes | null }): Buffer;
  evmAddress(pk: Bytes): Buffer;
  sealThreshold(pt: Bytes, n: number, k: number, o?: { aad?: Bytes | null }): { envelope: Buffer; shares: Buffer[] };
  openThreshold(env: Bytes, shares: Bytes[], o?: { aad?: Bytes | null }): Buffer;
  seal2(pt: Bytes, recipientKemPublic: Bytes, signerSigSecret: Bytes, o?: { aad?: Bytes | null; suite?: number }): Buffer;
  open2(env: Bytes, recipientKemSecret: Bytes, recipientKemPublic: Bytes, signerSigPublic: Bytes, o?: { aad?: Bytes | null }): Buffer;
  suiteOf(env: Bytes): number;
};
export const sealed: {
  newIdentity(tier?: number): Identity;
  inspect(env: Bytes): SealedInfo;
  addressedTo(env: Bytes, recipientPublic: Bytes): boolean;
  seal(tier: number, pt: Bytes, recipientPublic: Bytes, senderSecret: Bytes, opts?: SealedOptions | null): Buffer;
  open(tier: number, env: Bytes, recipientSecret: Bytes, recipientPublic: Bytes, senderPublic: Bytes, opts?: SealedOptions | null): Buffer;
  sealerBegin(tier: number, recipientPublic: Bytes, senderSecret: Bytes, opts?: SealedOptions | null): SealedStreamSealer;
  openerBegin(tier: number, preamble: Bytes, recipientSecret: Bytes, recipientPublic: Bytes, senderPublic: Bytes, opts?: SealedOptions | null): SealedStreamOpener;
};
export const session: {
  generateSessionPrekey(): KeyPair;
  initiateSession(responderPrekeyPublic: Bytes): Session;
  acceptSession(handshake: Bytes, prekeyPublic: Bytes, prekeySecret: Bytes): Session;
  generateSession2Prekey: typeof generateSession2Prekey;
  verifySession2Prekey: typeof verifySession2Prekey;
  claimedSession2Initiator: typeof claimedSession2Initiator;
  initiateSession2: typeof initiateSession2;
  acceptSession2: typeof acceptSession2;
};
export const pq: {
  mlKem: { keygen(level?: number): KeyPair; encapsulate(pk: Bytes, level?: number): Encapsulation; decapsulate(ct: Bytes, sk: Bytes, level?: number): Buffer };
  mlDsa: { keygen(level?: number): KeyPair; sign(msg: Bytes, sk: Bytes, level?: number): Buffer; verify(msg: Bytes, sig: Bytes, pk: Bytes, level?: number): boolean };
  slhDsa: { keygen(level?: number, hash?: number): KeyPair; sign(msg: Bytes, sk: Bytes, level?: number, hash?: number): Buffer; verify(msg: Bytes, sig: Bytes, pk: Bytes, level?: number, hash?: number): boolean };
  hybridKem: { keygen(): KeyPair; encapsulate(pk: Bytes): Encapsulation; decapsulate(ct: Bytes, sk: Bytes): Buffer };
  hybridSig: { keygen(): KeyPair; sign(msg: Bytes, sk: Bytes): Buffer; verify(msg: Bytes, sig: Bytes, pk: Bytes): boolean };
  sntrup: { keygen(): KeyPair; encapsulate(pk: Bytes): Encapsulation; decapsulate(ct: Bytes, sk: Bytes): Buffer };
  xwing: typeof XWing;
};
export const channel: {
  create(o: { initiator: boolean; staticPublic: Bytes; staticSecret: Bytes; prologue?: Bytes | null }): Noise;
};
export const frost: typeof Frost;
export const hpke: typeof Hpke;
export const ecvrf: typeof Ecvrf;
export const bbs: typeof Bbs;
export const oprf: typeof Oprf;
export const opaque: typeof Opaque;
export const rng: typeof Rng;
export const fips: typeof Fips;
