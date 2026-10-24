part of '../../cipher_bird.dart';

/// Encrypted steganography on bytes and the file key, off the calling thread.
extension CipherBirdAsyncMediaKeyed on CipherBird {
  /// [stegoEmbedEncryptedBytes] on [runner].
  Future<Uint8List> stegoEmbedEncryptedBytesAsync(
    Uint8List cover,
    MediaFormat format,
    Uint8List plaintext,
    Uint8List masterKey, {
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(
    EngineCallJob(
      symbol: 'cryptolib_stego_embed_encrypted',
      args: [
        JobArg.file(format.extension, cover),
        JobArg.bytes(plaintext),
        JobArg.out(format.extension),
        JobArg.bytes(masterKey),
      ],
      returns: JobReturn.result,
      cost: cover.length,
      inline: () => CipherBird.instance.stegoEmbedEncryptedBytes(
        cover,
        format,
        plaintext,
        masterKey,
      ),
      decodeReply: (r) => r.files.first,
    ),
  );

  /// [stegoExtractDecryptBytes] on [runner].
  Future<Uint8List> stegoExtractDecryptBytesAsync(
    Uint8List stego,
    MediaFormat format,
    Uint8List masterKey, {
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(
    EngineCallJob(
      symbol: 'cryptolib_stego_extract_decrypt',
      args: [JobArg.file(format.extension, stego), JobArg.bytes(masterKey)],
      returns: JobReturn.buffer,
      cost: stego.length,
      inline: () => CipherBird.instance.stegoExtractDecryptBytes(
        stego,
        format,
        masterKey,
      ),
      decodeReply: (r) => r.bytes,
    ),
  );

  /// [keyFromBytes] on [runner].
  Future<Uint8List> keyFromBytesAsync(
    Uint8List bytes, {
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(
    EngineCallJob(
      symbol: 'cryptolib_key_from_file',
      args: [JobArg.file('bin', bytes)],
      returns: JobReturn.buffer,
      cost: bytes.length,
      inline: () => CipherBird.instance.keyFromBytes(bytes),
      decodeReply: (r) => r.bytes,
    ),
  );
}
