part of 'live_playground.dart';

extension on LivePlayground {
  Future<void> drawKey() => attempt('draw key', () async {
    final before = _source().status().reseeds;
    final Uint8List bytes;
    try {
      bytes = _source().generate(32);
    } on Object catch (e) {
      say('refused: ${Playground.reason(e)}');
      return;
    }
    final after = _source().status().reseeds;
    meter.value = meter.value.seeded(after);
    _key = SymmetricKey.fromBytes(bytes, _lib);
    _keyHex.text = hexOf(bytes);
    say(
      'key drawn from the stream: ${Playground.brief(_keyHex.text)}'
      '${after > before ? ' (the generator ${before == 0 ? 'seeded' : 'reseeded'} first, seeding $after)' : ''}',
    );
  });

  Future<void> encrypt() => attempt('encrypt', () async {
    final k = _key;
    if (k == null) {
      say('draw a key first');
      return;
    }
    _cipher.text = k.encryptText(_message.text, aad: 'live');
    say(
      'encrypted ${_message.text.length} characters with XChaCha20-Poly1305 '
      'under the drawn key: ${Playground.brief(_cipher.text)}',
    );
  });

  Future<void> decrypt() => attempt('decrypt', () async {
    final k = _key;
    if (k == null) {
      say('draw a key first');
      return;
    }
    try {
      say('decrypted: ${k.decryptText(_cipher.text, aad: 'live')}');
    } on Object catch (e) {
      say('refused: ${Playground.reason(e)}');
    }
  });
}
