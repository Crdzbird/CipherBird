import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/playground.dart';
import 'package:cipherbird_example/util/bytes.dart';

/// A Session v2 chat between Alice and Bob, with Mallory trying to join.
final class SessionPlayground extends Playground {
  SessionPlayground(this._lib);

  final CipherBird _lib;
  late final _alice = _lib.hybridSigKeygen();
  late final _bob = _lib.hybridSigKeygen();
  late final _mallory = _lib.hybridSigKeygen();
  Session2? _a, _b;
  Uint8List? _last;
  final _aliceSays = PlayField('Alice says', text: 'hello Bob');
  final _bobSays = PlayField('Bob says', text: 'hello Alice');

  @override
  String get title => 'Session v2 chat';

  @override
  String get blurb =>
      'Bob publishes a signed prekey, Alice connects with her identity, both '
      'ratchet messages. Replays and strangers are refused.';

  @override
  List<PlayField> get fields => [_aliceSays, _bobSays];

  Future<void> _handshake(
    KeyPairResult initiator,
    String name,
  ) => attempt('handshake', () async {
    final prekey = _lib.generateSession2Prekey(_bob.secretKey);
    final a = _lib.initiateSession2(
      prekey.publicKey,
      _bob.publicKey,
      initiator.publicKey,
      initiator.secretKey,
    );
    final hs = a.handshake();
    say(
      '$name sent a ${hs.length}-byte handshake claiming ${hexOf(_lib.claimedSession2Initiator(hs)).substring(0, 16)}...',
    );
    final b = _lib.acceptSession2(
      hs,
      prekey.publicKey,
      prekey.secretKey,
      _bob.publicKey,
      _bob.secretKey,
      _alice.publicKey,
    );
    _a?.close();
    _b?.close();
    _a = a;
    _b = b;
    say('Bob accepted: the channel is up');
  });

  Future<void> _send(
    Session2? from,
    Session2? to,
    String text,
    String who,
  ) => attempt('send', () async {
    if (from == null || to == null) {
      say('no channel yet: run the handshake');
      return;
    }
    _last = from.encrypt(ascii(text));
    say(
      '$who -> ${String.fromCharCodes(to.decrypt(_last!))} (${_last!.length} bytes on the wire)',
    );
  });

  @override
  List<PlayAction> get actions => [
    PlayAction('Handshake as Alice', () => _handshake(_alice, 'Alice')),
    PlayAction('Handshake as Mallory', () => _handshake(_mallory, 'Mallory')),
    PlayAction('Alice sends', () => _send(_a, _b, _aliceSays.text, 'Alice')),
    PlayAction('Bob sends', () => _send(_b, _a, _bobSays.text, 'Bob')),
    PlayAction(
      'Replay last',
      () async => attempt('replay', () async {
        final last = _last;
        if (last == null || _b == null) {
          say('nothing to replay');
          return;
        }
        _b!.decrypt(last);
        say('replay accepted (should not happen)');
      }),
    ),
  ];
}
