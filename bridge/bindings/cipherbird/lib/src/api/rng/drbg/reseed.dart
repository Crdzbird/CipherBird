part of '../../../cipher_bird.dart';

extension DrbgReseed on Drbg {
  /// Reseed with fresh [entropy] plus optional [additional] input.
  void reseed(Uint8List entropy, [Uint8List? additional]) {
    final e = _lib._toNative(entropy);
    final add = _toNativeOrNull(additional);
    try {
      _lib._checkResult(
        _lib._lib.lookupFunction<
          CipherBirdResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CipherBirdResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_drbg_reseed')(
          _h,
          e,
          entropy.length,
          add,
          additional?.length ?? 0,
        ),
      );
    } finally {
      if (e != nullptr) {
        calloc.free(e);
      }
      if (add != nullptr) {
        calloc.free(add);
      }
    }
  }
}
