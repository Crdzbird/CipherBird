part of 'stego_playground.dart';

extension on StegoPlayground {
  Future<void> reveal() => attempt('reveal', () async {
    final pt = _revealWith(right: true);
    say('revealed: ${String.fromCharCodes(pt)}');
  });

  Future<void> revealWrong() => attempt('reveal with the wrong key', () async {
    if (_mode.picked('plain')) {
      final pt = _lib.stegoExtractBytes(_hiddenBytes, _format);
      say('plain mode has no key, anyone reveals: ${String.fromCharCodes(pt)}');
      return;
    }
    try {
      final pt = _revealWith(right: false);
      say('the wrong key revealed ${pt.length} bytes, which must not happen');
    } on Object catch (e) {
      say('wrong key refused: ${Playground.reason(e)}');
    }
  });

  Uint8List _revealWith({required bool right}) {
    final s = _hiddenBytes;
    final f = _format;
    const ppm = MediaFormat.ppmImage;
    return switch (_mode.value) {
      'plain' => _lib.stegoExtractBytes(s, f),
      'keyed placement' => _lib.stegoExtractKeyedBytes(s, f, _keyFor(right)),
      'encrypted' => _lib.stegoExtractDecryptBytes(s, f, _keyFor(right)),
      'physical seal (a photo is the key)' => _lib.physicalOpenBytes(
        keyMedia: right ? _keyPhoto : _otherPhoto,
        keyMediaFormat: ppm,
        stego: s,
        stegoFormat: f,
        aad: _aadBytes,
      ),
      'HPKE to Bob' => _lib.hpkeStegoOpenBytes(
        recipientSecret: (right ? _bob : _carol).secretKey,
        enc: _enc,
        stego: s,
        stegoFormat: f,
        aad: _aadBytes,
      ),
      'image factor (OPRF secret + reference photo)' =>
        _lib.imageFactorOpenBytes(
          oprfSecretSeed: right ? _oprfSeed : _lib.randomBytes(32),
          referenceImage: _keyPhoto,
          referenceFormat: ppm,
          stego: s,
          stegoFormat: f,
          aad: _aadBytes,
        ),
      _ =>
        _recipe
            .build(_sourceFor(right: right))
            .open(_lib.stegoExtractBytes(s, f)),
    };
  }
}
