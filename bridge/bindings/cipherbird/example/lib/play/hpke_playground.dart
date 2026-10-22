import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/playground.dart';
import 'package:cipherbird_example/util/bytes.dart';

/// HPKE to a recipient key, with the KEM chosen by the developer.
final class HpkePlayground extends Playground {
  HpkePlayground(this._lib) {
    _rekey(HpkeKem.xWing);
  }

  final CipherBird _lib;
  late HpkeKem _kem;
  late KeyPairResult _recipient;
  final _message = PlayField('Message', text: 'balance: 42', lines: 2);
  final _info = PlayField('Info', text: 'statement');
  final _enc = PlayField('Encapsulation (hex)', lines: 2);
  final _ct = PlayField('Ciphertext (hex, editable)', lines: 3);

  void _rekey(HpkeKem kem) {
    _kem = kem;
    _recipient = _lib.hpkeKeygenKem(kem);
    say(
      '${kem.name}: recipient public key ${_recipient.publicKey.length} bytes',
    );
  }

  @override
  String get title => 'HPKE with a chosen KEM';

  @override
  String get blurb =>
      'Pick DHKEM(X25519), ML-KEM-768 or X-Wing, seal a message to the '
      'recipient and open it. Edit the ciphertext to see it refused.';

  @override
  List<PlayField> get fields => [_message, _info, _enc, _ct];

  @override
  List<PlayAction> get actions => [
    for (final kem in HpkeKem.values)
      PlayAction('Use ${kem.name}', () async => _rekey(kem)),
    PlayAction(
      'Seal',
      () async => attempt('seal', () async {
        final s = _lib.hpkeSetupSKem(
          _kem,
          HpkeKdf.sha256,
          HpkeAead.aes256Gcm,
          HpkeMode.base,
          _recipient.publicKey,
          ascii(_info.text),
        );
        _enc.text = hexOf(s.enc);
        _ct.text = hexOf(s.context.seal(ascii(_message.text)));
        s.context.close();
        say('sealed with ${_kem.name}: enc ${s.enc.length} bytes');
      }),
    ),
    PlayAction(
      'Open',
      () async => attempt('open', () async {
        final r = _lib.hpkeSetupRKem(
          _kem,
          HpkeKdf.sha256,
          HpkeAead.aes256Gcm,
          HpkeMode.base,
          bytesOfHex(_enc.text),
          _recipient.secretKey,
          ascii(_info.text),
        );
        final pt = r.open(bytesOfHex(_ct.text));
        r.close();
        say('opened: ${String.fromCharCodes(pt)}');
      }),
    ),
  ];
}
