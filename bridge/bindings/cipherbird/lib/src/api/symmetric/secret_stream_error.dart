part of '../../cipher_bird.dart';

/// Why a SecretStream call did not succeed.
enum SecretStreamError {
  /// A key that is not 32 bytes or a header that is not 24.
  argument,

  /// The object was closed; its native state is gone.
  closed,

  /// The final chunk was already written or read; nothing may follow it.
  finished,

  /// The chunk did not authenticate: tampered, reordered, duplicated, from
  /// another stream or key, or shorter than the 17-byte overhead.
  invalid,

  /// The engine failed.
  internal,
}
