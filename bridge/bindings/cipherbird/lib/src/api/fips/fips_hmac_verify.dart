part of '../../cipher_bird.dart';

/// FIPS profile MAC verification on CipherBird.
extension CipherBirdFipsHmacVerify on CipherBird {
  /// Constant-time HMAC check.
  bool fipsHmacVerify(
    FipsHash hash,
    Uint8List key,
    Uint8List data,
    Uint8List tag,
  ) {
    final keyPtr = _toNative(key);
    final dataPtr = _toNative(data);
    final tagPtr = _toNative(tag);
    try {
      return _lib.lookupFunction<
            Int32 Function(
              Int32,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
            ),
            int Function(
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
            )
          >('cryptolib_fips_hmac_verify')(
            hash.value,
            keyPtr,
            key.length,
            dataPtr,
            data.length,
            tagPtr,
            tag.length,
          ) ==
          1;
    } finally {
      if (keyPtr != nullptr) calloc.free(keyPtr);
      if (dataPtr != nullptr) calloc.free(dataPtr);
      if (tagPtr != nullptr) calloc.free(tagPtr);
    }
  }
}
