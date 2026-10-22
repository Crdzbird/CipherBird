import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/playground.dart';
import 'package:cipherbird_example/util/bytes.dart';

/// Alice seals a signed envelope to Bob; Carol tries to open it.
final class Suite2Playground extends Playground {
  Suite2Playground(this._lib) {
    _people();
  }

  final CipherBird _lib;
  late KeyPairResult _alice, _bob, _carol;
  final _message = PlayField(
    'Message from Alice',
    text: 'wire 100 EUR to Bob',
    lines: 2,
  );
  final _aad = PlayField('Associated data', text: 'ctx');
  final _envelope = PlayField('Envelope (hex, editable)', lines: 3);

  void _people() {
    _alice = _lib.hybridSigKeygen();
    _bob = _lib.xwingKeygen();
    _carol = _lib.xwingKeygen();
    say('new people: Alice signs, Bob and Carol hold X-Wing keys');
  }

  Future<void> _open(String who, KeyPairResult kem) =>
      attempt('open as $who', () async {
        final pt = _lib.suite2Open(
          bytesOfHex(_envelope.text),
          kem.secretKey,
          kem.publicKey,
          _alice.publicKey,
          aad: ascii(_aad.text),
        );
        say('$who opened: ${String.fromCharCodes(pt)}');
      });

  @override
  String get title => 'Suite v2 envelopes';

  @override
  String get blurb =>
      'Seal to Bob. Opening as Carol fails because the signature covers '
      'the recipient; changing the associated data fails for the same reason.';

  @override
  List<PlayField> get fields => [_message, _aad, _envelope];

  @override
  List<PlayAction> get actions => [
    PlayAction('New people', () async => _people()),
    PlayAction(
      'Seal to Bob',
      () async => attempt('seal', () async {
        final env = _lib.suite2Seal(
          ascii(_message.text),
          _bob.publicKey,
          _alice.secretKey,
          aad: ascii(_aad.text),
        );
        _envelope.text = hexOf(env);
        say(
          'sealed: ${env.length} bytes, suite 0x${_lib.suite2SuiteOf(env).toRadixString(16)}',
        );
      }),
    ),
    PlayAction('Open as Bob', () => _open('Bob', _bob)),
    PlayAction('Open as Carol', () => _open('Carol', _carol)),
  ];
}
