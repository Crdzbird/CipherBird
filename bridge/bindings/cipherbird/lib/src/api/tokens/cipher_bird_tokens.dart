part of '../../cipher_bird.dart';

typedef _TokenFormatsNative = Size Function(Pointer<Uint8>, Size);
typedef _TokenFormats = int Function(Pointer<Uint8>, int);
typedef _TokenKeygenNative =
    Int32 Function(
      Pointer<Utf8>,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
      Pointer<Uint8>,
      Size,
      Pointer<Size>,
    );
typedef _TokenKeygen =
    int Function(
      Pointer<Utf8>,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
      Pointer<Uint8>,
      int,
      Pointer<Size>,
    );

/// The generic token API (`docs/TOKEN_API.md`): every format by name. A
/// format is its token header without the trailing dot (`v4.local`,
/// `cb1.local`, `cb1.public`); a `.local` format encrypts under a shared key,
/// a `.public` format signs with the secret half of a pair and verifies with
/// the public half. The caller always names the format it expects, and a
/// token whose header differs is [TokenStatus.invalid] before the key is
/// touched. The format-named methods ([pasetoV4LocalEncrypt],
/// [cb1LocalEncrypt] and their peers) are these calls with the format fixed.
extension CipherBirdTokens on CipherBird {
  /// Every format the engine knows, available in this build or not.
  List<TokenFormat> tokenFormats() {
    final f = _lib.lookupFunction<_TokenFormatsNative, _TokenFormats>(
      'cryptolib_token_formats',
    );
    final n = f(nullptr, 0);
    final out = calloc<Uint8>(n == 0 ? 1 : n);
    try {
      if (n == 0 || f(out, n) != n) {
        throw const TokenException(TokenStatus.internal, 'token table');
      }
      final list = jsonDecode(utf8.decode(out.asTypedList(n))) as List;
      return [
        for (final e in list) TokenFormat.fromJson(e as Map<String, Object?>),
      ];
    } finally {
      calloc.free(out);
    }
  }

  /// A fresh key for [format]: the shared key of a local format from the
  /// engine's CSPRNG, or both halves of a public format's pair.
  TokenKeys tokenKeygen(String format) {
    final f = _lib.lookupFunction<_TokenKeygenNative, _TokenKeygen>(
      'cryptolib_token_keygen',
    );
    const secretCap = 4096;
    const publicCap = 1984;
    final name = format.toNativeUtf8();
    final secret = calloc<Uint8>(secretCap);
    final public = calloc<Uint8>(publicCap);
    final secretLen = calloc<Size>();
    final publicLen = calloc<Size>();
    try {
      final rc = f(
        name,
        secret,
        secretCap,
        secretLen,
        public,
        publicCap,
        publicLen,
      );
      if (rc != 0) {
        throw TokenException(TokenStatus.fromCode(rc), format);
      }
      final sk = Uint8List.fromList(secret.asTypedList(secretLen.value));
      final pk = publicLen.value == 0
          ? null
          : Uint8List.fromList(public.asTypedList(publicLen.value));
      return TokenKeys(sk, pk);
    } finally {
      secret.asTypedList(secretCap).fillRange(0, secretCap, 0);
      calloc.free(secret);
      calloc.free(public);
      calloc.free(secretLen);
      calloc.free(publicLen);
      calloc.free(name);
    }
  }
}
