part of '../../cipher_bird.dart';

typedef _TokenCapNative = Size Function(Size);
typedef _TokenCap = int Function(int);

/// The one call shape every token consumer shares: a capacity helper, then
/// the engine writing the message into a buffer this side provides, which is
/// wiped whatever the verdict.
extension CipherBirdTokenOpen on CipherBird {
  Uint8List _tokenOpen(
    String capSymbol,
    String openSymbol,
    String format,
    String token,
    Uint8List key,
    Uint8List? expectedFooter,
    Uint8List? implicit,
  ) {
    final text = Uint8List.fromList(utf8.encode(token));
    final cap = _lib.lookupFunction<_TokenCapNative, _TokenCap>(capSymbol)(
      text.length,
    );
    if (cap == 0) {
      throw TokenException(TokenStatus.invalid, format);
    }
    final out = calloc<Uint8>(cap);
    final outLen = calloc<Size>();
    final pt = _toNative(text);
    final pk = _toNative(key);
    final pf = expectedFooter == null ? nullptr : _toNative(expectedFooter);
    final pi = implicit == null ? nullptr : _toNative(implicit);
    try {
      final rc = _lib.lookupFunction<_TokenCallNative, _TokenCall>(openSymbol)(
        out,
        cap,
        outLen,
        pt,
        text.length,
        pk,
        key.length,
        pf,
        expectedFooter?.length ?? 0,
        pi,
        implicit?.length ?? 0,
      );
      if (rc != 0) {
        throw TokenException(TokenStatus.fromCode(rc), format);
      }
      return Uint8List.fromList(out.asTypedList(outLen.value));
    } finally {
      out.asTypedList(cap).fillRange(0, cap, 0);
      for (final p in [pt, pk, pf, pi]) {
        if (p != nullptr) calloc.free(p);
      }
      calloc.free(outLen);
      calloc.free(out);
    }
  }
}
