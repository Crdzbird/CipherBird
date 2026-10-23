part of 'live_playground.dart';

/// How the key follows the stream.
const liveRefreshModes = [
  'on every credited chunk',
  'on every reseed',
  'manual',
];

extension on LivePlayground {
  /// Draws a key and re-encrypts after a credited chunk, as the refresh
  /// mode asks; silent in the log, the meter counts the keys.
  void autoKey(LiveFeedReport r) {
    if (!r.accepted || _refresh.picked('manual') || !r.ready) {
      return;
    }
    final m = meter.value;
    if (_refresh.picked('on every reseed') &&
        m.creditedSinceReseed < m.minCredit) {
      return;
    }
    final bytes = _source().generate(32);
    meter.value = meter.value.seeded(_source().status().reseeds);
    final k = SymmetricKey.fromBytes(bytes, _lib);
    _key = k;
    _keyHex.text = hexOf(bytes);
    if (_message.text.isNotEmpty) {
      _cipher.text = k.encryptText(_message.text, aad: 'live');
    }
  }

  ResolutionPreset get _preset => switch (_resolution.value) {
    'high' => ResolutionPreset.high,
    'medium' => ResolutionPreset.medium,
    _ => ResolutionPreset.low,
  };

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
