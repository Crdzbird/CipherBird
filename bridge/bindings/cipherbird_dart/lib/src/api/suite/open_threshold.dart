part of '../../cryptolib.dart';

/// Suite - one-call advanced combinations.
///
/// A high-level facade that composes hybrid KEM, hybrid signatures,
/// MolecularVault, media entropy, keyring, Shamir and Keccak into single calls.
/// Every seal is authenticated and fails closed; the post-quantum envelopes are
/// self-describing (they carry the KEM ciphertext), so a recipient needs only
/// their long-term secret key. Requires the native library built with OpenSSL
/// and post-quantum support.
extension CryptoLibSuiteOpenThreshold on CryptoLib {
  /// Reconstruct the master from any k of the shares and open the envelope.
  Uint8List suiteOpenThreshold(
    Uint8List envelope,
    List<Uint8List> shares, {
    Uint8List? aad,
  }) {
    final blob = BytesBuilder();
    for (final s in shares) {
      blob.add(s);
    }
    final joined = blob.toBytes();
    final pe = _toNative(envelope);
    final ps = _toNative(joined);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_suite_open_threshold')(
          pe,
          envelope.length,
          ps,
          joined.length,
          pa,
          aad?.length ?? 0,
        ),
      );
    } finally {
      if (pe != nullptr) {
        calloc.free(pe);
      }
      if (ps != nullptr) {
        calloc.free(ps);
      }
      if (pa != nullptr) {
        calloc.free(pa);
      }
    }
  }
}
