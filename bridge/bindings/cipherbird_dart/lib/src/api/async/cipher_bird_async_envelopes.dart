part of '../../cipher_bird.dart';

/// Suite v2 envelopes off the calling thread.
extension CipherBirdAsyncEnvelopes on CipherBird {
  /// [suite2Seal] on [runner].
  Future<Uint8List> suite2SealAsync(
    Uint8List plaintext,
    Uint8List recipientKemPublic,
    Uint8List signerSigSecret, {
    Uint8List? aad,
    Suite2Id suite = Suite2Id.xWingSig,
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) {
    final a = aad ?? Uint8List(0);
    return runner.run(
      EngineCallJob(
        symbol: 'cryptolib_suite2_seal',
        args: [
          JobArg.bytes(plaintext),
          JobArg.bytes(recipientKemPublic),
          JobArg.bytes(signerSigSecret),
          JobArg.bytes(a),
          JobArg.i32(suite.value),
        ],
        returns: JobReturn.buffer,
        cost: 1 << 17,
        inline: () => CipherBird.instance.suite2Seal(
          plaintext,
          recipientKemPublic,
          signerSigSecret,
          aad: aad,
          suite: suite,
        ),
        decodeReply: (r) => r.bytes,
      ),
    );
  }

  /// [suite2Open] on [runner].
  Future<Uint8List> suite2OpenAsync(
    Uint8List envelope,
    Uint8List recipientKemSecret,
    Uint8List recipientKemPublic,
    Uint8List signerSigPublic, {
    Uint8List? aad,
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) {
    final a = aad ?? Uint8List(0);
    return runner.run(
      EngineCallJob(
        symbol: 'cryptolib_suite2_open',
        args: [
          JobArg.bytes(envelope),
          JobArg.bytes(recipientKemSecret),
          JobArg.bytes(recipientKemPublic),
          JobArg.bytes(signerSigPublic),
          JobArg.bytes(a),
        ],
        returns: JobReturn.buffer,
        cost: 1 << 17,
        inline: () => CipherBird.instance.suite2Open(
          envelope,
          recipientKemSecret,
          recipientKemPublic,
          signerSigPublic,
          aad: aad,
        ),
        decodeReply: (r) => r.bytes,
      ),
    );
  }
}
