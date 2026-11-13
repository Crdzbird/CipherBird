part of '../../cipher_bird.dart';

typedef _P256BufNative = CipherBirdBufferResult Function(Pointer<Uint8>, Size);
typedef _P256Buf = CipherBirdBufferResult Function(Pointer<Uint8>, int);

/// P-256 (secp256r1) ECDSA with SHA-256, the ES256 of JSON Web Signatures.
///
/// The secret key is the 32-byte scalar, the public key the 65-byte
/// uncompressed point `0x04 || X || Y`, the signature the raw 64-byte
/// `r || s`. Every curve operation runs in the engine's OpenSSL libcrypto.
/// The engines bundled for Android, iOS and the web carry a libcrypto
/// trimmed of elliptic curves, so [p256Available] is false there and the
/// other calls throw; on those devices the platform's own P-256 is reached
/// through `DeviceFips`.
extension CipherBirdP256 on CipherBird {
  int _p256Mode() => _lib.lookupFunction<Int32 Function(), int Function()>(
    'cryptolib_p256_available',
  )();

  /// Whether the loaded engine carries P-256.
  bool p256Available() => _p256Mode() != 0;

  /// Whether [p256Sign] derives its nonce from the key and the message
  /// (RFC 6979), so the same input always gives the same signature.
  bool p256DeterministicNonces() => _p256Mode() == 2;

  /// A fresh key pair: a 32-byte secret key and its 65-byte public key.
  KeyPairResult p256GenerateKey() {
    final pair = _extractKeyPair(
      _lib.lookupFunction<
        CipherBirdKeyPair Function(),
        CipherBirdKeyPair Function()
      >('cryptolib_p256_keygen')(),
    );
    if (pair.secretKey.length != 32) {
      throw Exception('p256 not enabled in this build');
    }
    return pair;
  }

  /// The 65-byte public key of a 32-byte [secretKey]. Throws for another
  /// length or a scalar outside 1..n-1.
  Uint8List p256PublicKey(Uint8List secretKey) =>
      _p256Bytes('cryptolib_p256_public_key', secretKey);

  Uint8List _p256Bytes(String symbol, Uint8List input) {
    final p = _toNative(input);
    try {
      return _checkBufResult(
        _lib.lookupFunction<_P256BufNative, _P256Buf>(symbol)(p, input.length),
      );
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }
}
