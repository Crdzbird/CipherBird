part of '../../cipher_bird.dart';

/// Signing and verifying with P-256; see [CipherBirdP256].
extension CipherBirdP256Sign on CipherBird {
  /// ECDSA over SHA-256([message]) under a 32-byte [secretKey]: the raw
  /// 64-byte `r || s` a JWS ES256 signature carries. The message is hashed
  /// inside the call. `s` is not normalised, so a signature is malleable and
  /// must not serve as an identifier.
  Uint8List p256Sign(Uint8List secretKey, Uint8List message) {
    final sk = _toNative(secretKey);
    final msg = _toNative(message);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
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
          )
        >('cryptolib_p256_sign')(sk, secretKey.length, msg, message.length),
      );
    } finally {
      if (sk != nullptr) calloc.free(sk);
      if (msg != nullptr) calloc.free(msg);
    }
  }

  /// Whether [signature], 64 bytes of `r || s` with each half in 1..n-1,
  /// verifies over SHA-256([message]) under a 65-byte uncompressed
  /// [publicKey] on the curve. Any other length, range or encoding is false.
  /// Both halves of the `s` range are accepted, as JWS requires.
  bool p256Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) {
    final pk = _toNative(publicKey);
    final msg = _toNative(message);
    final sig = _toNative(signature);
    try {
      return _lib.lookupFunction<
            Int32 Function(
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
            ),
            int Function(
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
            )
          >('cryptolib_p256_verify')(
            pk,
            publicKey.length,
            msg,
            message.length,
            sig,
            signature.length,
          ) ==
          1;
    } finally {
      if (pk != nullptr) calloc.free(pk);
      if (msg != nullptr) calloc.free(msg);
      if (sig != nullptr) calloc.free(sig);
    }
  }
}
