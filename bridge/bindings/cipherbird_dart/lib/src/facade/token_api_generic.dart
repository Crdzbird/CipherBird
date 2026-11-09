part of '../cipher_bird.dart';

/// The generic half of `lib.tokens`: every format by name
/// (`docs/TOKEN_API.md`). The format-named members of [TokenApi] are these
/// calls with the format fixed.
extension TokenApiGeneric on TokenApi {
  /// Every format the engine knows, available in this build or not.
  List<TokenFormat> formats() => _l.tokenFormats();

  /// A fresh key or pair for [format].
  TokenKeys keygen(String format) => _l.tokenKeygen(format);

  /// Issue a token in [format]: encrypt (local) or sign (public).
  String issue(
    String format,
    Uint8List key,
    Uint8List payload, {
    Uint8List? footer,
    Uint8List? implicit,
  }) => _l.tokenIssue(format, key, payload, footer: footer, implicit: implicit);

  /// Accept a token as [format]: decrypt (local) or verify (public).
  Uint8List accept(
    String format,
    String token,
    Uint8List key, {
    Uint8List? expectedFooter,
    Uint8List? implicit,
  }) => _l.tokenAccept(
    format,
    token,
    key,
    expectedFooter: expectedFooter,
    implicit: implicit,
  );

  /// The header of [token] as a format name, unverified.
  String peekFormat(String token) => _l.tokenPeekFormat(token);

  /// The decoded footer of [token], unverified; null when it has none.
  Uint8List? peekFooter(String token) => _l.tokenPeekFooter(token);
}
