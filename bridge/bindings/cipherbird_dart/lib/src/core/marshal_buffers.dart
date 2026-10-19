part of '../cipher_bird.dart';

extension _MarshalBuffers on CipherBird {
  Uint8List _copyBuf(CipherBirdBuffer buf) {
    if (buf.data == nullptr || buf.len == 0) {
      return Uint8List(0);
    }
    final out = Uint8List(buf.len);
    out.setAll(0, buf.data.asTypedList(buf.len));
    final ptr = calloc<CipherBirdBuffer>();
    ptr.ref.data = buf.data;
    ptr.ref.len = buf.len;
    _core.bufferFree(ptr);
    calloc.free(ptr);
    return out;
  }

  Uint8List _checkBufResult(CipherBirdBufferResult r) {
    if (r.error != nullptr) {
      final msg = r.error.toDartString();
      _core.strFree(r.error);
      throw Exception(msg);
    }
    return _copyBuf(r.buf);
  }

  void _checkResult(CipherBirdResult r) {
    if (r.ok != 1) {
      final msg = r.error != nullptr ? r.error.toDartString() : 'Unknown error';
      if (r.error != nullptr) {
        _core.strFree(r.error);
      }
      throw Exception(msg);
    }
    if (r.error != nullptr) {
      _core.strFree(r.error);
    }
  }

  /// A NUL-terminated native copy of a password given as bytes, in memory
  /// that is wiped on free. A password containing a zero byte ends there.
  Pointer<Utf8> _toNativeZ(Uint8List password) {
    final ptr = calloc<Uint8>(password.length + 1);
    ptr.asTypedList(password.length + 1)
      ..setAll(0, password)
      ..[password.length] = 0;
    return ptr.cast<Utf8>();
  }

  Pointer<Uint8> _toNative(Uint8List data) {
    if (data.isEmpty) {
      return nullptr;
    }
    final ptr = calloc<Uint8>(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    return ptr;
  }
}
