part of '../../cryptolib_ffi.dart';

/// Domain-grouped entry points into the full CryptoLib surface.
extension CryptoLibNamespaces on CryptoLib {
  /// Hashes, MACs, password hashing and HKDF.
  HashApi get hash => HashApi(this);

  /// Authenticated symmetric encryption, incl. committing and streaming modes.
  AeadApi get aead => AeadApi(this);

  /// X25519 key exchange, Ed25519 signing, boxes and sealed boxes.
  AsymApi get asym => AsymApi(this);

  /// BLS12-381 signing, verification and aggregation.
  BlsApi get bls => BlsApi(this);

  /// Layered vaults: Vault, asymmetric Vault and MolecularVault.
  VaultApi get vault => VaultApi(this);

  /// Envelope encryption with revocable device and passphrase slots.
  KeyringApi get keyring => KeyringApi(this);

  /// Media-derived entropy and entropy-source health.
  EntropyApi get entropy => EntropyApi(this);

  /// Steganographic embedding, extraction and carrier diagnostics.
  StegoApi get stego => StegoApi(this);

  /// Carriers that combine encryption with concealment, plus FEC.
  ComposedApi get composed => ComposedApi(this);

  /// EVM and Bitcoin interop primitives.
  ChainApi get chain => ChainApi(this);

  /// One-call composed recipes (PQ seal, threshold, file-keyed, keyring-backed).
  SuiteApi get suite => SuiteApi(this);

  /// Flagship / Fortress sealed messaging.
  SealedApi get sealed => SealedApi(this);

  /// Forward-secret ratcheting sessions.
  SessionApi get session => SessionApi(this);

  /// FROST t-of-n threshold signatures.
  FrostApi get frost => FrostApi(this);

  /// HPKE (RFC 9180) hybrid public-key encryption.
  HpkeApi get hpke => HpkeApi(this);

  /// ECVRF (RFC 9381) verifiable random function.
  EcvrfApi get ecvrf => EcvrfApi(this);

  /// BBS anonymous credentials: selective disclosure, pseudonyms, blind issuance.
  BbsApi get bbs => BbsApi(this);

  /// Oblivious pseudorandom function (RFC 9497).
  OprfApi get oprf => OprfApi(this);

  /// OPAQUE password-authenticated key exchange.
  OpaqueApi get opaque => OpaqueApi(this);

  /// Random bytes and explicitly-seeded generators.
  RngApi get rng => RngApi(this);

  /// Post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA and hybrids).
  PqApi get pq => PqApi(this);

  /// Noise XX secure channel.
  NoiseApi get channel => NoiseApi(this);
}
