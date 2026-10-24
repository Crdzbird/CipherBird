part of '../../cipher_bird.dart';

/// The hybrid signature off the calling thread.
extension CipherBirdAsyncHybrid on CipherBird {
  /// [hybridSigSign] on [runner].
  Future<Uint8List> hybridSigSignAsync(
    Uint8List msg,
    Uint8List secretKey, {
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(
    EngineCallJob(
      symbol: 'cryptolib_hybrid_sig_sign',
      args: [JobArg.bytes(msg), JobArg.bytes(secretKey)],
      returns: JobReturn.buffer,
      cost: 1 << 16,
      inline: () => CipherBird.instance.hybridSigSign(msg, secretKey),
      decodeReply: (r) => r.bytes,
    ),
  );
}
