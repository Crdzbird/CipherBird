part of 'stego_playground.dart';

extension on StegoPlayground {
  KeySource _sourceFor({required bool right}) => switch (_recipeKey.value) {
    'raw key' => RawKeySource(_keyFor(right)),
    'key photo' => KeyBytesSource(right ? _keyPhoto : _otherPhoto),
    _ => PassphraseKeySource(right ? _passphrase.text : 'wrong $_passphrase'),
  };

  Future<void> inspect() => attempt('inspect', () async {
    for (final (name, bytes) in [
      ('cover', _coverBytes),
      ('hidden', _hiddenBytes),
    ]) {
      if (bytes.isEmpty) {
        say('$name: nothing yet');
        continue;
      }
      final r = _lib.stegoInspectBytes(bytes, _format);
      say(
        '$name: ${r.parses ? 'parses' : 'does not parse'} as '
        '${r.format.name}, ${r.width}x${r.height}, ${r.fileSize} bytes'
        '${r.detail.isEmpty ? '' : ', ${r.detail}'}',
      );
    }
  });

  Future<void> detectHidden() => attempt('detect', () async {
    for (final (name, bytes) in [
      ('cover', _coverBytes),
      ('hidden', _hiddenBytes),
    ]) {
      if (bytes.isEmpty) {
        continue;
      }
      final r = _lib.stegoDetectHiddenBytes(bytes, _format);
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

  Future<void> damage({required bool heavy}) => attempt('damage', () async {
    final (bytes, n) = damaged(
      _hiddenBytes,
      header: _ext == 'ppm' ? 20 : 44,
      count: heavy ? 4096 : 32,
      mask: heavy ? 0xF0 : 0x01,
    );
    _hiddenBytes = bytes;
    await _show(_hidden, bytes);
    say(
      '$n bytes ${heavy ? 'rewritten' : 'nudged by one'} across the '
      'middle of the file; press Reveal to see whether the payload survived',
    );
  });

  Future<void> describeRecipe() => attempt('describe', () async {
    say(_recipe.build(_sourceFor(right: true)).describe().trimRight());
  });
}
