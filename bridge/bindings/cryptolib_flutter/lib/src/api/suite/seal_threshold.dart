part of '../../cryptolib.dart';

/// Suite - one-call advanced combinations.
///
/// A high-level facade that composes hybrid KEM, hybrid signatures,
/// MolecularVault, media entropy, keyring, Shamir and Keccak into single calls.
/// Every seal is authenticated and fails closed; the post-quantum envelopes are
/// self-describing (they carry the KEM ciphertext), so a recipient needs only
/// their long-term secret key. Requires the native library built with OpenSSL
/// and post-quantum support.
extension CryptoLibSuiteSealThreshold on CryptoLib {
  /// Threshold (k-of-n): seal under a fresh master, split it into [n] Shamir
  /// shares of which any [k] reconstruct it. Returns the envelope and the [n]
  /// individual share records; distribute the shares, keep the envelope
  /// anywhere. Open with [suiteOpenThreshold] using any `k` of the shares.
  (Uint8List envelope, List<Uint8List> shares) suiteSealThreshold(
    Uint8List plaintext,
    int n,
    int k, {
    Uint8List? aad,
  }) {
    final pp = _toNative(plaintext);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    final outShares = calloc<CryptoBuffer>();
    try {
      final r = _lib
          .lookupFunction<
            CryptoBufferResult Function(
              Pointer<Uint8>,
              Size,
              Uint8,
              Uint8,
              Pointer<Uint8>,
              Size,
              Pointer<CryptoBuffer>,
            ),
            CryptoBufferResult Function(
              Pointer<Uint8>,
              int,
              int,
              int,
              Pointer<Uint8>,
              int,
              Pointer<CryptoBuffer>,
            )
          >(
            'cryptolib_suite_seal_threshold',
          )(pp, plaintext.length, n, k, pa, aad?.length ?? 0, outShares);
      final env = _checkBufResult(r);
      final blob = _copyBuf(outShares.ref);
      return (env, _splitShareRecords(blob));
    } finally {
      if (pp != nullptr) {
        calloc.free(pp);
      }
      if (pa != nullptr) {
        calloc.free(pa);
      }
      calloc.free(outShares);
    }
  }
}
