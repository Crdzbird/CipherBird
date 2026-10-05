part of '../../cipher_bird.dart';

/// Hashing operations.
extension CipherBirdHkdf on CipherBird {
  /// HKDF-SHA256 expand: derive [outLen] bytes of output key material from a
  /// pseudorandom key [prk] and optional [info] context.
  Uint8List hkdfExpand(Uint8List prk, {Uint8List? info, int outLen = 32}) {
    final pp = _toNative(prk);
    final pi = (info != null && info.isNotEmpty) ? _toNative(info) : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Size,
          ),
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            int,
          )
        >('cryptolib_hkdf_expand')(
          pp,
          prk.length,
          pi,
          info?.length ?? 0,
          outLen,
        ),
      );
    } finally {
      if (pp != nullptr) {
        calloc.free(pp);
      }
      if (pi != nullptr) {
        calloc.free(pi);
      }
    }
  }

  /// HKDF-SHA256 extract: PRK = HMAC(salt, IKM). Pass an empty [salt] for the
  /// all-zero default. Returns a 32-byte pseudorandom key.
  Uint8List hkdfExtract(Uint8List ikm, {Uint8List? salt}) {
    final ps = (salt != null && salt.isNotEmpty) ? _toNative(salt) : nullptr;
    final pk = _toNative(ikm);
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
        >('cryptolib_hkdf_extract')(ps, salt?.length ?? 0, pk, ikm.length),
      );
    } finally {
      if (ps != nullptr) {
        calloc.free(ps);
      }
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }
}
