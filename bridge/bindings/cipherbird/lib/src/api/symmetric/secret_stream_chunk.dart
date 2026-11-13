part of '../../cipher_bird.dart';

/// One chunk a [SecretStreamDecryptor] opened: its plaintext and the tag the
/// writer gave it.
final class SecretStreamChunk {
  /// Builds the chunk; the decryptor does.
  const SecretStreamChunk(this.plaintext, this.tag);

  /// The decrypted bytes; wipe them when they hold secrets.
  final Uint8List plaintext;

  /// The authenticated tag of the chunk.
  final SecretStreamTag tag;

  /// Whether this is the last chunk of the stream.
  bool get isFinal => tag == SecretStreamTag.finalChunk;
}
