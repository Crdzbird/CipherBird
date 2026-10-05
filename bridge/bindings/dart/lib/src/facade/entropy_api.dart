part of '../../cryptolib_ffi.dart';

/// Media-derived entropy and entropy-source health.
extension type EntropyApi(CryptoLib _l) {
  /// Harvest entropy from a file (LavaRand mode).
  Pointer<Void> fromFile(String path) => _l.entropyFromFile(path);

  /// Harvest entropy from a file (deterministic mode).
  Pointer<Void> fromFileDeterministic(String path) =>
      _l.entropyFromFileDeterministic(path);

  /// Harvest entropy from multiple files (LavaRand mode).
  Pointer<Void> fromFiles(List<String> paths) => _l.entropyFromFiles(paths);

  /// Harvest entropy from multiple files (deterministic mode).
  Pointer<Void> fromFilesDeterministic(List<String> paths) =>
      _l.entropyFromFilesDeterministic(paths);

  /// Derive all 6 domain-separated keys at once.
  DerivedKeysResult deriveAll(Pointer<Void> handle) =>
      _l.entropyDeriveAll(handle);

  /// Derive a 32-byte symmetric key from an entropy handle.
  Uint8List symmetricKey(Pointer<Void> handle) =>
      _l.entropySymmetricKey(handle);

  /// Get the 64-byte raw mixed entropy.
  Uint8List raw(Pointer<Void> handle) => _l.entropyRaw(handle);

  /// Get the 32-byte entropy boost key.
  Uint8List boost(Pointer<Void> handle) => _l.entropyBoost(handle);

  /// Get entropy info.
  EntropyInfoResult info(Pointer<Void> handle) => _l.entropyInfo(handle);

  /// Get a full asymmetric bundle from entropy.
  AsymBundleResult asymBundle(Pointer<Void> handle) =>
      _l.entropyAsymBundle(handle);

  /// Refresh system entropy in-place.
  void refresh(Pointer<Void> handle) => _l.entropyRefresh(handle);

  /// Free an entropy handle.
  void free(Pointer<Void> handle) => _l.entropyFree(handle);

  /// One-liner: get a 32-byte key from any file.
  Uint8List keyFromFile(String path) => _l.keyFromFile(path);

  /// One-liner: encrypt plaintext using a file as the key.
  Packet sealFromFile(String path, String plaintext, String aad) =>
      _l.sealFromFile(path, plaintext, aad);

  /// One-liner: decrypt a packet using a file as the key.
  Uint8List openFromFile(String path, Packet pkt, String aad) =>
      _l.openFromFile(path, pkt, aad);

  /// Assess a media file against the SP 800-90B health tests. [maxBytes] caps the
  /// sample size (0 = default 1 MiB). Use before trusting a file as a key source.
  HealthReport assessFileHealth(String path, [int maxBytes = 0]) =>
      _l.assessFileHealth(path, maxBytes);
}
