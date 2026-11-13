part of '../cipher_bird.dart';

/// What the SecretStream objects share: argument and state checks, typed
/// errors for engine results, and the finalizers of their native handles.
extension _StreamSupport on CipherBird {
  static final Map<CipherBird, Map<String, HandleFinalizer>> _finalizers =
      Map.identity();

  HandleFinalizer _handleFinalizer(String freeSymbol) =>
      (_finalizers[this] ??= {})[freeSymbol] ??= HandleFinalizer(
        _lib,
        freeSymbol,
      );

  void _streamLength(Uint8List bytes, int length, String message) {
    if (bytes.length != length) {
      throw SecretStreamException(SecretStreamError.argument, message);
    }
  }

  void _streamUsable(Pointer<Void> handle, bool finished) {
    if (handle == nullptr) {
      throw const SecretStreamException(SecretStreamError.closed);
    }
    if (finished) {
      throw const SecretStreamException(SecretStreamError.finished);
    }
  }

  Uint8List _streamBuf(CipherBirdBufferResult r, SecretStreamError error) {
    if (r.error != nullptr) {
      final detail = r.error.toDartString();
      _core.strFree(r.error);
      throw SecretStreamException(error, detail);
    }
    return _copyBuf(r.buf);
  }
}
