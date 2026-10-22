part of 'stego_playground.dart';

extension on StegoPlayground {
  KeySource _sourceFor({required bool right}) => switch (_recipeKey.value) {
    'raw key' => RawKeySource(_keyFor(right)),
    'key photo' => KeyFileSource(right ? _keyPhoto : _otherPhoto),
    _ => PassphraseKeySource(right ? _passphrase.text : 'wrong $_passphrase'),
  };

  Future<void> inspect() => attemptWithFiles('inspect', () async {
    for (final name in [_coverName, _hiddenName]) {
      final r = _lib.stegoInspect(_files.path(name));
      say(
        '$name: ${r.parses ? 'parses' : 'does not parse'} as '
        '${r.format.name}, ${r.width}x${r.height}, ${r.fileSize} bytes, '
        'extension ${r.extensionMatches ? 'matches' : 'lies'}'
        '${r.detail.isEmpty ? '' : ', ${r.detail}'}',
      );
    }
  });

  Future<void> detectHidden() => attemptWithFiles('detect', () async {
    for (final name in [_coverName, _hiddenName]) {
      final r = _lib.stegoDetectHidden(_files.path(name));
      say(
        '$name: unkeyed cipherbird payload ${r.cipherbirdPayload ? 'found' : 'not found'}, '
        'LSB likelihood ${r.lsbEmbeddingLikelihood.toStringAsFixed(2)} over '
        '${r.samplesAnalysed} samples',
      );
    }
    say(
      'a keyed, encrypted or sealed payload is never found this way; '
      'only a plain one is, and the LSB score reads natural images, not these',
    );
  });

  Future<void> damage({required bool heavy}) =>
      attemptWithFiles('damage', () async {
        final n = _files.corrupt(
          _hiddenName,
          header: _ext == 'ppm' ? 20 : 44,
          count: heavy ? 4096 : 32,
          mask: heavy ? 0xF0 : 0x01,
        );
        await _show(_hidden, _hiddenName);
        say(
          '$n bytes ${heavy ? 'rewritten' : 'nudged by one'} across the '
          'middle of the file; press Reveal to see whether the payload '
          'survived',
        );
      });

  Future<void> describeRecipe() => attemptWithFiles('describe', () async {
    say(_recipe.build(_sourceFor(right: true)).describe().trimRight());
  });
}
