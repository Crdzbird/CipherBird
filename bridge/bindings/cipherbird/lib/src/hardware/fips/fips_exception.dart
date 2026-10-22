/// A validated-module operation failed. [code] is stable across platforms:
/// `unsupported`, `authentication_failed`, `bad_argument` or `failed`.
final class FipsException implements Exception {
  const FipsException(this.code, this.message);

  /// The stable failure code.
  final String code;

  /// Platform detail.
  final String message;

  @override
  String toString() => 'FipsException($code): $message';
}
