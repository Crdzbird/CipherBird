part of '../../cipher_bird.dart';

typedef _TokenAcceptCapNative = Size Function(Pointer<Utf8>, Size);
typedef _TokenAcceptCap = int Function(Pointer<Utf8>, int);

/// Accepting a token of any format (`docs/TOKEN_API.md`).
extension CipherBirdTokenAccept on CipherBird {
  /// Accepts [token] as [format]: decrypts it under [key] for a local format,
  /// or verifies it with [key], the public half of a pair, for a public
  /// format, and returns the payload. The token's header must be [format];
  /// any other header is [TokenStatus.invalid], decided before the key is
  /// used, so the header inside a token never chooses the algorithm.
  /// [expectedFooter] and [implicit] must match exactly, and every failure
  /// that depends on the token is the one [TokenStatus.invalid] verdict. The
  /// buffer the engine wrote into is wiped whatever the verdict.
  Uint8List tokenAccept(
    String format,
    String token,
    Uint8List key, {
    Uint8List? expectedFooter,
    Uint8List? implicit,
  }) {
    final text = Uint8List.fromList(utf8.encode(token));
    final name = format.toNativeUtf8();
    final cap = _lib.lookupFunction<_TokenAcceptCapNative, _TokenAcceptCap>(
      'cryptolib_token_accept_cap',
    )(name, text.length);
    final out = calloc<Uint8>(cap == 0 ? 1 : cap);
    final outLen = calloc<Size>();
    final pt = _toNative(text);
    final pk = _toNative(key);
    final pf = expectedFooter == null ? nullptr : _toNative(expectedFooter);
    final pi = implicit == null ? nullptr : _toNative(implicit);
    try {
      final rc =
          _lib.lookupFunction<_TokenNamedCallNative, _TokenNamedCall>(
            'cryptolib_token_accept',
          )(
            name,
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
      if (cap == 0) {
        throw TokenException(TokenStatus.invalid, format);
      }
      return Uint8List.fromList(out.asTypedList(outLen.value));
    } finally {
      if (cap != 0) out.asTypedList(cap).fillRange(0, cap, 0);
      for (final p in [pt, pk, pf, pi]) {
        if (p != nullptr) calloc.free(p);
      }
      calloc.free(outLen);
      calloc.free(out);
      calloc.free(name);
    }
  }
}
