part of '../../cipher_bird.dart';

/// Hashing operations.
extension CipherBirdHmacSha256 on CipherBird {
  /// Verify an HMAC-SHA256 tag in constant time. Returns true if valid.
  bool hmacSha256Verify(Uint8List msg, Uint8List mac, Uint8List key) {
    final pm = _toNative(msg), pmac = _toNative(mac), pk = _toNative(key);
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
          >('cryptolib_hmac_sha256_verify')(
            pm,
            msg.length,
            pmac,
            mac.length,
            pk,
            key.length,
          ) ==
          1;
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
      if (pmac != nullptr) {
        calloc.free(pmac);
      }
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }

  /// HMAC-SHA256. [key] should be >= 32 bytes. Returns a 32-byte tag.
  Uint8List hmacSha256(Uint8List msg, Uint8List key) {
    final pm = _toNative(msg), pk = _toNative(key);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)
        >('cryptolib_hmac_sha256')(pm, msg.length, pk, key.length),
      );
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }
}
