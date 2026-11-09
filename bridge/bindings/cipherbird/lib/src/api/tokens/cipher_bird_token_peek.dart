part of '../../cipher_bird.dart';

typedef _TokenPeekFormatNative =
    Size Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _TokenPeekFormat =
    int Function(Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _TokenPeekFooterNative =
    Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _TokenPeekFooter =
    int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);

/// Reading a token before verifying it (`docs/TOKEN_API.md`). Nothing these
/// return is trusted until [CipherBirdTokenAccept.tokenAccept] succeeds.
extension CipherBirdTokenPeek on CipherBird {
  /// The header of [token] as a format name (`cb1.local`), UNVERIFIED, or an
  /// empty string when the text has no header of the known shape. The name
  /// need not be a format this engine knows; a verifier checks it against
  /// its own allow-list and then calls [tokenAccept] with the format it chose.
  String tokenPeekFormat(String token) {
    if (token.isEmpty) return '';
    final text = Uint8List.fromList(utf8.encode(token));
    final f = _lib.lookupFunction<_TokenPeekFormatNative, _TokenPeekFormat>(
      'cryptolib_token_peek_format',
    );
    final pt = _toNative(text);
    try {
      final n = f(pt, text.length, nullptr, 0);
      if (n == 0) return '';
      final out = calloc<Uint8>(n);
      try {
        f(pt, text.length, out, n);
        return String.fromCharCodes(out.asTypedList(n));
      } finally {
        calloc.free(out);
      }
    } finally {
      calloc.free(pt);
    }
  }

  /// The decoded footer of [token], UNVERIFIED, the usual place for a key id,
  /// so a verifier can pick a key; null when the token has no footer. Throws
  /// [TokenStatus.invalid] when the text has no header of the known shape or
  /// the footer is not base64url. The footer [tokenAccept] compares is the
  /// caller's expected footer, never the one read here.
  Uint8List? tokenPeekFooter(String token) {
    final text = Uint8List.fromList(utf8.encode(token));
    final f = _lib.lookupFunction<_TokenPeekFooterNative, _TokenPeekFooter>(
      'cryptolib_token_peek_footer',
    );
    final cap = text.isEmpty ? 1 : text.length;
    final pt = _toNative(text);
    final out = calloc<Uint8>(cap);
    final outLen = calloc<Size>();
    try {
      final rc = f(pt, text.length, out, cap, outLen);
      if (rc != 0) {
        throw TokenException(TokenStatus.fromCode(rc), 'token');
      }
      if (outLen.value == 0) return null;
      return Uint8List.fromList(out.asTypedList(outLen.value));
    } finally {
      calloc.free(outLen);
      calloc.free(out);
      calloc.free(pt);
    }
  }
}
