part of '../cipher_bird.dart';

extension _MarshalLists on CipherBird {
  (Pointer<Pointer<Uint8>>, Pointer<Size>) _toNativeList(
    List<Uint8List> items,
  ) {
    final n = items.length;
    final ptrs = calloc<Pointer<Uint8>>(n);
    final lens = calloc<Size>(n);
    for (var i = 0; i < n; i++) {
      final b = items[i];
      final p = calloc<Uint8>(b.isEmpty ? 1 : b.length);
      if (b.isNotEmpty) {
        p.asTypedList(b.length).setAll(0, b);
      }
      ptrs[i] = p;
      lens[i] = b.length;
    }
    return (ptrs, lens);
  }

  void _freeNativeList(
    Pointer<Pointer<Uint8>> ptrs,
    Pointer<Size> lens,
    int n,
  ) {
    for (var i = 0; i < n; i++) {
      if (ptrs[i] != nullptr) {
        calloc.free(ptrs[i]);
      }
    }
    calloc.free(ptrs);
    calloc.free(lens);
  }
}
