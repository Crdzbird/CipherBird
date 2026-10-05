part of '../../cipher_bird.dart';

extension CipherBirdHkdfDerive on CipherBird {
  /// HKDF-SHA256 one-shot (extract + expand): derive [outLen] bytes from [ikm]
  /// with optional [salt] and [info].
  Uint8List hkdfDerive(
    Uint8List ikm, {
    Uint8List? salt,
    Uint8List? info,
    int outLen = 32,
  }) {
    final pk = _toNative(ikm);
    final ps = (salt != null && salt.isNotEmpty) ? _toNative(salt) : nullptr;
    final pi = (info != null && info.isNotEmpty) ? _toNative(info) : nullptr;
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
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            int,
          )
        >('cryptolib_hkdf_derive')(
          pk,
          ikm.length,
          ps,
          salt?.length ?? 0,
          pi,
          info?.length ?? 0,
          outLen,
        ),
      );
    } finally {
      if (pk != nullptr) {
        calloc.free(pk);
      }
      if (ps != nullptr) {
        calloc.free(ps);
      }
      if (pi != nullptr) {
        calloc.free(pi);
      }
    }
  }
}
