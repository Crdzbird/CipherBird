part of '../../cipher_bird.dart';

/// Suite - one-call advanced combinations.
///
/// A high-level facade that composes hybrid KEM, hybrid signatures,
/// MolecularVault, media entropy, keyring, Shamir and Keccak into single calls.
/// Every seal is authenticated and fails closed; the post-quantum envelopes are
/// self-describing (they carry the KEM ciphertext), so a recipient needs only
/// their long-term secret key. Requires the native library built with OpenSSL
/// and post-quantum support.
extension CipherBirdSuiteTwoBufferCall on CipherBird {
  Uint8List _suiteBuf(String symbol, Uint8List a, Uint8List b, Uint8List? aad) {
    final pa = _toNative(a), pb = _toNative(b);
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >(symbol)(pa, a.length, pb, b.length, pad, aad?.length ?? 0),
      );
    } finally {
      if (pa != nullptr) {
        calloc.free(pa);
      }
      if (pb != nullptr) {
        calloc.free(pb);
      }
      if (pad != nullptr) {
        calloc.free(pad);
      }
    }
  }
}
