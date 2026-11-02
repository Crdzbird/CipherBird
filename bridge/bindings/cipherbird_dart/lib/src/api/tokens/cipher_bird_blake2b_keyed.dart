part of '../../cipher_bird.dart';

typedef _Blake2bIntoNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
    );
typedef _Blake2bInto =
    int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);

/// BLAKE2b at a chosen output length on CipherBird.
extension CipherBirdBlake2bKeyed on CipherBird {
  /// BLAKE2b of [msg] computed natively at [outLen] bytes (1 to 64): the
  /// output length is a BLAKE2b parameter, so this is not a truncation of
  /// [blake2b]. [key] is absent (unkeyed) or 16 to 64 bytes; with a key the
  /// result is a MAC or key material.
  Uint8List blake2bKeyed(Uint8List msg, {Uint8List? key, int outLen = 32}) {
    final pm = _toNative(msg);
    final pk = key == null ? nullptr : _toNative(key);
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
        >('cryptolib_blake2b_keyed')(
          pm,
          msg.length,
          pk,
          key?.length ?? 0,
          outLen,
        ),
      );
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// [blake2bKeyed] written into [out], whose length (1 to 64) selects the
  /// digest length; returns [out]. The engine fills the digest in one call
  /// and allocates nothing.
  Uint8List blake2bKeyedInto(Uint8List out, Uint8List msg, {Uint8List? key}) {
    final po = calloc<Uint8>(out.length);
    final pm = _toNative(msg);
    final pk = key == null ? nullptr : _toNative(key);
    try {
      final rc = _lib.lookupFunction<_Blake2bIntoNative, _Blake2bInto>(
        'cryptolib_blake2b_keyed_into',
      )(po, out.length, pm, msg.length, pk, key?.length ?? 0);
      if (rc != 0) {
        throw TokenException(TokenStatus.fromCode(rc), 'BLAKE2b');
      }
      out.setAll(0, po.asTypedList(out.length));
      return out;
    } finally {
      calloc.free(po);
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }
}
