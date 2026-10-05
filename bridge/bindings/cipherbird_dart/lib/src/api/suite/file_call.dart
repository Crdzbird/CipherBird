part of '../../cipher_bird.dart';

/// Suite - one-call advanced combinations.
///
/// A high-level facade that composes hybrid KEM, hybrid signatures,
/// MolecularVault, media entropy, keyring, Shamir and Keccak into single calls.
/// Every seal is authenticated and fails closed; the post-quantum envelopes are
/// self-describing (they carry the KEM ciphertext), so a recipient needs only
/// their long-term secret key. Requires the native library built with OpenSSL
/// and post-quantum support.
extension CipherBirdSuiteFileCall on CipherBird {
  Uint8List _suiteFile(
    String symbol,
    Uint8List data,
    String path,
    Uint8List? aad,
  ) {
    final pd = _toNative(data);
    final cp = path.toNativeUtf8();
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
          )
        >(symbol)(pd, data.length, cp, pad, aad?.length ?? 0),
      );
    } finally {
      if (pd != nullptr) {
        calloc.free(pd);
      }
      calloc.free(cp);
      if (pad != nullptr) {
        calloc.free(pad);
      }
    }
  }
}
