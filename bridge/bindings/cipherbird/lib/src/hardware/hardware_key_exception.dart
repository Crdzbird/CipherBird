/// A hardware key operation failed. [code] is stable across platforms:
/// `unsupported`, `not_found`, `exists`, `authentication_failed`,
/// `bad_argument` or `failed`.
final class HardwareKeyException implements Exception {
  const HardwareKeyException(this.code, this.message);

  /// The stable failure code.
  final String code;

  /// Platform detail.
  final String message;

  /// Whether the user failed or cancelled the biometric prompt.
  bool get isAuthenticationFailure => code == 'authentication_failed';

  @override
  String toString() => 'HardwareKeyException($code): $message';
}
