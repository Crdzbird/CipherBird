part of '../../cipher_bird.dart';

/// Steganography on bytes, off the calling thread.
extension CipherBirdAsyncMedia on CipherBird {
  /// [stegoEmbedBytes] on [runner].
  Future<Uint8List> stegoEmbedBytesAsync(
    Uint8List cover,
    MediaFormat format,
    Uint8List payload, {
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(
    EngineCallJob(
      symbol: 'cryptolib_stego_embed',
      args: [
        JobArg.file(format.extension, cover),
        JobArg.bytes(payload),
        JobArg.out(format.extension),
      ],
      returns: JobReturn.result,
      cost: cover.length,
      inline: () => CipherBird.instance.stegoEmbedBytes(cover, format, payload),
      decodeReply: (r) => r.files.first,
    ),
  );

  /// [stegoExtractBytes] on [runner].
  Future<Uint8List> stegoExtractBytesAsync(
    Uint8List stego,
    MediaFormat format, {
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(
    EngineCallJob(
      symbol: 'cryptolib_stego_extract',
      args: [JobArg.file(format.extension, stego)],
      returns: JobReturn.buffer,
      cost: stego.length,
      inline: () => CipherBird.instance.stegoExtractBytes(stego, format),
      decodeReply: (r) => r.bytes,
    ),
  );
}
