part of '../../cipher_bird.dart';

/// A token call that did not succeed, with the engine's verdict.
final class TokenException implements Exception {
  /// Builds the exception for [status] on [format] (such as `cb1.local`).
  const TokenException(this.status, this.format);

  /// Why the call failed.
  final TokenStatus status;

  /// The token format the call was about.
  final String format;

  @override
  String toString() => switch (status) {
    TokenStatus.invalid => 'cipherbird: invalid $format token',
    TokenStatus.argument => 'cipherbird: $format argument out of range',
    TokenStatus.unavailable =>
      'cipherbird: $format is not available in this build profile',
    _ => 'cipherbird: $format backend failure',
  };
}
