part of '../../cipher_bird.dart';

/// Suite - one-call advanced combinations.
///
/// A high-level facade that composes hybrid KEM, hybrid signatures,
/// MolecularVault, media entropy, keyring, Shamir and Keccak into single calls.
/// Every seal is authenticated and fails closed; the post-quantum envelopes are
/// self-describing (they carry the KEM ciphertext), so a recipient needs only
/// their long-term secret key. Requires the native library built with OpenSSL
/// and post-quantum support.
extension CipherBirdSuiteKeyringFactorCall on CipherBird {
  Uint8List _suiteKeyringFactor(
    String symbol,
    Uint8List data,
    Pointer<Void> keyring,
    Uint8List factor,
    Uint8List? aad,
  ) {
    final pd = _toNative(data), pf = _toNative(factor);
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Void>,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >(symbol)(
          pd,
          data.length,
          keyring,
          pf,
          factor.length,
          pad,
          aad?.length ?? 0,
        ),
      );
    } finally {
      if (pd != nullptr) {
        calloc.free(pd);
      }
      if (pf != nullptr) {
        calloc.free(pf);
      }
      if (pad != nullptr) {
        calloc.free(pad);
      }
    }
  }
}
