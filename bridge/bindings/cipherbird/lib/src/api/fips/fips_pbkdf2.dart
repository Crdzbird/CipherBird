part of '../../cipher_bird.dart';

/// FIPS profile password derivation and randomness on CipherBird.
extension CipherBirdFipsPbkdf2 on CipherBird {
  /// PBKDF2 (SP 800-132): salt at least 16 bytes, iterations at least 1000.
  Uint8List fipsPbkdf2(
    FipsHash hash,
    Uint8List password,
    Uint8List salt, {
    int iterations = 600000,
    int outLen = 32,
  }) {
    final passwordPtr = _toNative(password);
    final saltPtr = _toNative(salt);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Int32,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Uint32,
            Size,
          ),
          CipherBirdBufferResult Function(
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            int,
            int,
          )
        >('cryptolib_fips_pbkdf2')(
          hash.value,
          passwordPtr,
          password.length,
          saltPtr,
          salt.length,
          iterations,
          outLen,
        ),
      );
    } finally {
      if (passwordPtr != nullptr) calloc.free(passwordPtr);
      if (saltPtr != nullptr) calloc.free(saltPtr);
    }
  }

  /// Bytes from the module DRBG.
  Uint8List fipsRandom(int n) {
    return _checkBufResult(
      _lib.lookupFunction<
        CipherBirdBufferResult Function(Size),
        CipherBirdBufferResult Function(int)
      >('cryptolib_fips_random')(n),
    );
  }
}
