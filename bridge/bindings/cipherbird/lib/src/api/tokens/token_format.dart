part of '../../cipher_bird.dart';

/// One entry of the engine's token table (`docs/TOKEN_API.md`): a format is
/// named by its token header without the trailing dot, such as `v4.local`,
/// `cb1.local` or `cb1.public`. A local format encrypts under a shared key of
/// [keyBytes]; a public format signs with the [secretKeyBytes] half of a pair
/// and verifies with the [publicKeyBytes] half. [available] is false where
/// the format is not in the linked profile; its calls then throw the
/// unavailable status.
final class TokenFormat {
  /// Builds an entry; the engine's table is read with [TokenFormat.fromJson].
  const TokenFormat({
    required this.format,
    required this.purpose,
    required this.standard,
    required this.keyBytes,
    required this.publicKeyBytes,
    required this.secretKeyBytes,
    required this.signatureBytes,
    required this.maxInputBytes,
    required this.available,
  });

  /// Reads one object of the engine's JSON table.
  factory TokenFormat.fromJson(Map<String, Object?> json) => TokenFormat(
    format: json['format']! as String,
    purpose: json['purpose']! as String,
    standard: json['standard']! as String,
    keyBytes: (json['key_bytes']! as num).toInt(),
    publicKeyBytes: (json['public_key_bytes']! as num).toInt(),
    secretKeyBytes: (json['secret_key_bytes']! as num).toInt(),
    signatureBytes: (json['signature_bytes']! as num).toInt(),
    maxInputBytes: (json['max_input_bytes']! as num).toInt(),
    available: json['available']! as bool,
  );

  /// The format name, the token header without its trailing dot.
  final String format;

  /// `local` (encrypts and decrypts) or `public` (signs and verifies).
  final String purpose;

  /// `PASETO v4` for a published specification followed byte for byte,
  /// `library-native` for CipherBird's own.
  final String standard;

  /// The shared key length of a local format; 0 for a public one.
  final int keyBytes;

  /// The verifying half of a public format's pair; 0 for a local one.
  final int publicKeyBytes;

  /// The signing half of a public format's pair; 0 for a local one.
  final int secretKeyBytes;

  /// The signature a public format appends; 0 for a local one.
  final int signatureBytes;

  /// The largest payload, footer or implicit assertion the format takes.
  final int maxInputBytes;

  /// Whether this build of the engine has the format.
  final bool available;

  /// Whether the format signs and verifies rather than encrypts and decrypts.
  bool get isPublic => purpose == 'public';

  @override
  String toString() =>
      '$format ($purpose, $standard${available ? '' : ', unavailable'})';
}
