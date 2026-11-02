part of '../../cipher_bird.dart';

/// Outcome of a token call, the engine's return code.
enum TokenStatus {
  /// The token was produced or opened.
  ok(0),

  /// The token failed in a way that depends on its content: format, header,
  /// encoding, footer, tag or signature. One verdict for all of them, so a
  /// caller cannot be used as an oracle.
  invalid(-1),

  /// A caller error that does not depend on the token: a key of the wrong
  /// length, an input over the maximum, a buffer too small.
  argument(-2),

  /// The engine failed.
  internal(-3),

  /// The linked engine is the bank profile, which ships only standards-track
  /// formats; cb1 tokens are absent there.
  unavailable(-4);

  const TokenStatus(this.code);

  /// The C ABI return code.
  final int code;

  /// The status for an engine return code; unknown codes read as [internal].
  static TokenStatus fromCode(int code) => TokenStatus.values.firstWhere(
    (s) => s.code == code,
    orElse: () => TokenStatus.internal,
  );
}
