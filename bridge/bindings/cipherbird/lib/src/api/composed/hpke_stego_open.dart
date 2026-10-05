part of '../../cryptolib.dart';

/// Composed seal/open operations on CryptoLib.
extension CryptoLibComposedHpkeStegoOpen on CryptoLib {
  /// Open an [hpkeStegoSeal]ed carrier with the recipient secret key and the
  /// `enc` value returned by the sealer. [aad] and [info] must match.
  Uint8List hpkeStegoOpen({
    required Uint8List recipientSecret,
    required Uint8List enc,
    required String stegoPath,
    Uint8List? aad,
    Uint8List? info,
  }) {
    final sk = _toNative(recipientSecret);
    final e = _toNative(enc);
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final i = (info == null || info.isEmpty) ? nullptr : _toNative(info);
    final sp = stegoPath.toNativeUtf8();
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
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
          )
        >('cryptolib_hpke_stego_open')(
          sk,
          recipientSecret.length,
          e,
          enc.length,
          a,
          aad?.length ?? 0,
          i,
          info?.length ?? 0,
          sp,
        ),
      );
    } finally {
      if (sk != nullptr) {
        calloc.free(sk);
      }
      if (e != nullptr) {
        calloc.free(e);
      }
      if (a != nullptr) {
        calloc.free(a);
      }
      if (i != nullptr) {
        calloc.free(i);
      }
      calloc.free(sp);
    }
  }
}
