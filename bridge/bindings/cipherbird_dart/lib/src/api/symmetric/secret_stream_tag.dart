part of '../../cipher_bird.dart';

/// The tag every SecretStream chunk carries, authenticated with it
/// (libsodium `crypto_secretstream_xchacha20poly1305`).
enum SecretStreamTag {
  /// An ordinary chunk.
  message(0),

  /// The end of a set of chunks that belong together, not of the stream.
  push(1),

  /// An ordinary chunk after which both sides switch to a fresh key.
  rekey(2),

  /// The last chunk. A stream that ends without one was truncated.
  finalChunk(3);

  const SecretStreamTag(this.value);

  /// The byte the engine reads and writes.
  final int value;

  /// The tag for an engine byte.
  static SecretStreamTag fromValue(int value) => values.firstWhere(
    (t) => t.value == value,
    orElse: () => throw SecretStreamException(
      SecretStreamError.internal,
      'unknown chunk tag $value',
    ),
  );
}
