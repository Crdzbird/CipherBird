part of '../../cipher_bird.dart';

typedef _TokenIssueLenNative = Size Function(Pointer<Utf8>, Size, Size);
typedef _TokenIssueLen = int Function(Pointer<Utf8>, int, int);
typedef _TokenNamedCallNative =
    Int32 Function(
      Pointer<Utf8>,
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
typedef _TokenNamedCall =
    int Function(
      Pointer<Utf8>,
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

/// Issuing a token of any format (`docs/TOKEN_API.md`).
extension CipherBirdTokenIssue on CipherBird {
  /// Issues a token in [format]: encrypts [payload] under [key] for a local
  /// format, or signs it with [key], the secret half of a pair, for a public
  /// format. The [footer] travels in clear and is authenticated; the
  /// [implicit] assertion is authenticated but never stored. Throws
  /// [TokenException] with [TokenStatus.format] for an unknown format,
  /// [TokenStatus.unavailable] for one this build lacks and
  /// [TokenStatus.argument] for a key of the wrong length or an input over
  /// the format's maximum.
  String tokenIssue(
    String format,
    Uint8List key,
    Uint8List payload, {
    Uint8List? footer,
    Uint8List? implicit,
  }) {
    final name = format.toNativeUtf8();
    final len = _lib.lookupFunction<_TokenIssueLenNative, _TokenIssueLen>(
      'cryptolib_token_issue_len',
    )(name, payload.length, footer?.length ?? 0);
    final out = calloc<Uint8>(len == 0 ? 1 : len);
    final outLen = calloc<Size>();
    final pk = _toNative(key);
    final pm = _toNative(payload);
    final pf = footer == null ? nullptr : _toNative(footer);
    final pi = implicit == null ? nullptr : _toNative(implicit);
    try {
      final rc =
          _lib.lookupFunction<_TokenNamedCallNative, _TokenNamedCall>(
            'cryptolib_token_issue',
          )(
            name,
            out,
            len,
            outLen,
            pk,
            key.length,
            pm,
            payload.length,
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
      calloc.free(name);
    }
  }
}
