part of '../../cipher_bird.dart';

/// The post-quantum signatures off the calling thread: a background isolate
/// natively, the engine worker in the browser, through [EngineCallJob].
extension CipherBirdAsyncSignatures on CipherBird {
  /// A static tear-off: it captures nothing, so it crosses into an isolate.
  static KeyPairResult _pair(EngineReply r) {
    final (pk, sk) = r.keyPair;
    return KeyPairResult(publicKey: pk, secretKey: sk);
  }

  /// [mlDsaKeygen] on [runner].
  Future<KeyPairResult> mlDsaKeygenAsync(
    MlDsaLevel level, {
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(
    EngineCallJob(
      symbol: 'cryptolib_ml_dsa_keygen',
      args: [JobArg.i32(level.value)],
      returns: JobReturn.keypair,
      cost: 1 << 16,
      inline: () => CipherBird.instance.mlDsaKeygen(level),
      decodeReply: _pair,
    ),
  );

  /// [mlDsaSign] on [runner].
  Future<Uint8List> mlDsaSignAsync(
    Uint8List msg,
    Uint8List secretKey,
    MlDsaLevel level, {
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(
    EngineCallJob(
      symbol: 'cryptolib_ml_dsa_sign',
      args: [
        JobArg.bytes(msg),
        JobArg.bytes(secretKey),
        JobArg.i32(level.value),
      ],
      returns: JobReturn.buffer,
      cost: 1 << 16,
      inline: () => CipherBird.instance.mlDsaSign(msg, secretKey, level),
      decodeReply: (r) => r.bytes,
    ),
  );

  /// [slhDsaKeygen] on [runner].
  Future<KeyPairResult> slhDsaKeygenAsync(
    SlhDsaLevel level,
    SlhDsaHash hash, {
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(
    EngineCallJob(
      symbol: 'cryptolib_slh_dsa_keygen',
      args: [JobArg.i32(level.value), JobArg.i32(hash.value)],
      returns: JobReturn.keypair,
      cost: 1 << 22,
      inline: () => CipherBird.instance.slhDsaKeygen(level, hash),
      decodeReply: _pair,
    ),
  );

  /// [slhDsaSign] on [runner].
  Future<Uint8List> slhDsaSignAsync(
    Uint8List msg,
    Uint8List secretKey,
    SlhDsaLevel level,
    SlhDsaHash hash, {
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(
    EngineCallJob(
      symbol: 'cryptolib_slh_dsa_sign',
      args: [
        JobArg.bytes(msg),
        JobArg.bytes(secretKey),
        JobArg.i32(level.value),
        JobArg.i32(hash.value),
      ],
      returns: JobReturn.buffer,
      cost: 1 << 22,
      inline: () => CipherBird.instance.slhDsaSign(msg, secretKey, level, hash),
      decodeReply: (r) => r.bytes,
    ),
  );
}
