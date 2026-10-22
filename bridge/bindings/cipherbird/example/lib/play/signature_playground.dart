import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/playground.dart';

/// Sign and verify with Ed25519 or the Ed25519 + ML-DSA-65 hybrid.
final class SignaturePlayground extends Playground {
  SignaturePlayground(this._lib) {
    _rekey(SignatureAlgorithm.hybrid);
  }

  final CipherBird _lib;
  late SigningKey _signer;
  final _message = PlayField('Message', text: 'release 4.1.0', lines: 2);
  final _signature = PlayField('Signature (base64, editable)', lines: 3);
  final _public = PlayField('Public key (hex)');

  void _rekey(SignatureAlgorithm algorithm) {
    _signer = SigningKey.generate(algorithm: algorithm, lib: _lib);
    _public.text = _signer.publicKey.hex;
    say(
      'new ${algorithm.name} key, public key ${_public.text.length ~/ 2} bytes',
    );
  }

  @override
  String get title => 'Signatures';

  @override
  String get blurb =>
      'Sign a message, then change the message or the signature and verify '
      'again. Switch algorithms to compare signature sizes.';

  @override
  List<PlayField> get fields => [_message, _signature, _public];

  @override
  List<PlayAction> get actions => [
    PlayAction('Ed25519 key', () async => _rekey(SignatureAlgorithm.ed25519)),
    PlayAction('Hybrid key', () async => _rekey(SignatureAlgorithm.hybrid)),
    PlayAction(
      'Sign',
      () async => attempt('sign', () async {
        _signature.text = _signer.signText(_message.text);
        say('signed: ${_signature.text.length} base64 chars');
      }),
    ),
    PlayAction(
      'Verify',
      () async => attempt('verify', () async {
        final ok = _signer.verifyKey.verifyText(_message.text, _signature.text);
        say(ok ? 'signature verifies' : 'signature does NOT verify');
      }),
    ),
  ];
}
