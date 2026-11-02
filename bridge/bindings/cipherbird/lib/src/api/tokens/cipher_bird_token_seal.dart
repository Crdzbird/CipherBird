part of '../../cipher_bird.dart';

typedef _TokenLenNative = Size Function(Size, Size);
typedef _TokenLen = int Function(int, int);
typedef _TokenCallNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
    );
typedef _TokenCall =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Size>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
    );

/// The one call shape every token producer shares: a length helper, then the
/// engine writing the token text into a buffer this side provides.
extension CipherBirdTokenSeal on CipherBird {
  String _tokenSeal(
    String lenSymbol,
    String sealSymbol,
    String format,
    Uint8List key,
    Uint8List message,
    Uint8List? footer,
    Uint8List? implicit,
  ) {
    final len = _lib.lookupFunction<_TokenLenNative, _TokenLen>(lenSymbol)(
      message.length,
      footer?.length ?? 0,
    );
    if (len == 0) {
      throw TokenException(TokenStatus.argument, format);
    }
    final out = calloc<Uint8>(len);
    final outLen = calloc<Size>();
    final pk = _toNative(key);
    final pm = _toNative(message);
    final pf = footer == null ? nullptr : _toNative(footer);
    final pi = implicit == null ? nullptr : _toNative(implicit);
    try {
      final rc = _lib.lookupFunction<_TokenCallNative, _TokenCall>(sealSymbol)(
        out,
        len,
        outLen,
        pk,
        key.length,
        pm,
        message.length,
        pf,
        footer?.length ?? 0,
        pi,
        implicit?.length ?? 0,
      );
      if (rc != 0) {
        throw TokenException(TokenStatus.fromCode(rc), format);
      }
      return String.fromCharCodes(out.asTypedList(outLen.value));
    } finally {
      for (final p in [pk, pm, pf, pi]) {
        if (p != nullptr) calloc.free(p);
      }
      calloc.free(outLen);
      calloc.free(out);
    }
  }
}
