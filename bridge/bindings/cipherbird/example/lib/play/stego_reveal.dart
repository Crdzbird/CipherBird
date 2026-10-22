part of 'stego_playground.dart';

extension on StegoPlayground {
  Future<void> reveal() => attemptWithFiles('reveal', () async {
    final pt = _revealWith(right: true);
    say('revealed: ${String.fromCharCodes(pt)}');
  });

  Future<void> revealWrong() => attemptWithFiles(
    'reveal with the wrong key',
    () async {
      if (_mode.picked('plain')) {
        final pt = _lib.stegoExtract(_hiddenPath);
        say(
          'plain mode has no key, anyone reveals: ${String.fromCharCodes(pt)}',
        );
        return;
      }
      try {
        final pt = _revealWith(right: false);
        say('the wrong key revealed ${pt.length} bytes, which must not happen');
      } on Object catch (e) {
        say('wrong key refused: ${Playground.reason(e)}');
      }
    },
  );

  Uint8List _revealWith({required bool right}) => switch (_mode.value) {
    'plain' => _lib.stegoExtract(_hiddenPath),
    'keyed placement' => _lib.stegoExtractKeyed(_hiddenPath, _keyFor(right)),
    'encrypted' => _lib.stegoExtractDecrypt(_hiddenPath, _keyFor(right)),
    'physical seal (a photo is the key)' => _lib.physicalOpen(
      keyMediaPath: right ? _keyPhoto : _otherPhoto,
      stegoPath: _hiddenPath,
      aad: _aadBytes,
    ),
    'HPKE to Bob' => _lib.hpkeStegoOpen(
      recipientSecret: (right ? _bob : _carol).secretKey,
      enc: _enc,
      stegoPath: _hiddenPath,
      aad: _aadBytes,
    ),
    'image factor (OPRF secret + reference photo)' => _lib.imageFactorOpen(
      oprfSecretSeed: right ? _oprfSeed : _lib.randomBytes(32),
      referenceImagePath: _keyPhoto,
      stegoPath: _hiddenPath,
      aad: _aadBytes,
    ),
    _ => _recipe.build(_sourceFor(right: right)).openFromCarrier(_hiddenPath),
  };

  Uint8List _keyFor(bool right) => right ? _keyBytes : _lib.randomBytes(32);
}
