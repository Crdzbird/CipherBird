part of '../../cipher_bird.dart';

/// A SecretStream call that did not succeed.
final class SecretStreamException implements Exception {
  /// Builds the exception for [error], with the engine's [detail] if any.
  const SecretStreamException(this.error, [this.detail]);

  /// Why the call failed.
  final SecretStreamError error;

  /// What the engine or the binding said about it.
  final String? detail;

  @override
  String toString() => switch (error) {
    SecretStreamError.argument => 'cipherbird: secret stream: $detail',
    SecretStreamError.closed => 'cipherbird: this secret stream was closed',
    SecretStreamError.finished =>
      'cipherbird: this secret stream already carried its final chunk',
    SecretStreamError.invalid =>
      'cipherbird: secret stream chunk rejected (${detail ?? 'invalid'})',
    SecretStreamError.internal =>
      'cipherbird: secret stream failure (${detail ?? 'engine'})',
  };
}
