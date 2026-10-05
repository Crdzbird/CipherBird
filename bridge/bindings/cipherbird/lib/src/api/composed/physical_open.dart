part of '../../cryptolib.dart';

/// Composed seal/open operations on CryptoLib.
extension CryptoLibComposedPhysicalOpen on CryptoLib {
  /// Recover a [physicalSeal]ed message. Requires the same key media file and
  /// the same [aad].
  Uint8List physicalOpen({
    required String keyMediaPath,
    required String stegoPath,
    Uint8List? aad,
  }) {
    final km = keyMediaPath.toNativeUtf8();
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final sp = stegoPath.toNativeUtf8();
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
          ),
          CryptoBufferResult Function(
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
          )
        >('cryptolib_physical_open')(km, a, aad?.length ?? 0, sp),
      );
    } finally {
      calloc.free(km);
      if (a != nullptr) {
        calloc.free(a);
      }
      calloc.free(sp);
    }
  }
}
