part of 'entropy_playground.dart';

extension on EntropyPlayground {
  Future<void> sealWithFile() => attemptWithFiles('seal with file', () async {
    final pkt = _lib.sealFromFile(_path, _message.text, _aad.text);
    say(
      'sealed with the file as the key: ${pkt.ciphertext.length} bytes of '
      'ciphertext, salt ${hexOf(pkt.kdfSalt)}',
    );
    final back = _lib.openFromFile(_path, pkt, _aad.text);
    say('opened with the same file: ${String.fromCharCodes(back)}');
    try {
      _lib.openFromFile(_otherPath, pkt, _aad.text);
      say('another photo opened it, which must not happen');
    } on Object catch (e) {
      say('another photo refused: ${Playground.reason(e)}');
    }
  });

  Future<void> seedDrbg() => attemptWithFiles('drbg', () async {
    final raw = _raw();
    final a = _lib.drbg(raw, personalization: ascii('playground'));
    final b = _lib.drbg(raw, personalization: ascii('playground'));
    try {
      final first = a.generate(32);
      final second = a.generate(32);
      say('HMAC-DRBG seeded by the harvest: ${hexOf(first)}');
      say('next 32 bytes: ${hexOf(second)}');
      say(
        same(first, b.generate(32))
            ? 'a second DRBG on the same seed replays the stream'
            : 'a second DRBG on the same seed diverged, which must not happen',
      );
    } finally {
      a.close();
      b.close();
    }
  });

  Future<void> feedFortuna() => attemptWithFiles('fortuna', () async {
    final f = _lib.fortuna();
    try {
      f.addEntropy(1, _raw());
      f.reseed();
      say(
        'Fortuna fed with the harvest, reseed ${f.reseedCount()}: '
        '${hexOf(f.generate(32))}',
      );
      say('and again: ${hexOf(f.generate(32))}');
    } finally {
      f.close();
    }
  });

  Future<void> recipeWithFile() => attemptWithFiles('recipe', () async {
    final recipe = _recipe.build(KeyFileSource(_path));
    say(recipe.describe().trimRight());
    final clock = Stopwatch()..start();
    final envelope = recipe.seal(ascii(_message.text));
    say(
      'sealed under the file-derived key: ${envelope.length} bytes in '
      '${clock.elapsedMilliseconds} ms',
    );
    say('opened: ${String.fromCharCodes(recipe.open(envelope))}');
    try {
      _recipe.build(KeyFileSource(_otherPath)).open(envelope);
      say('another photo opened it, which must not happen');
    } on Object catch (e) {
      say('another photo refused: ${Playground.reason(e)}');
    }
  });
}
