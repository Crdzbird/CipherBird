import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/playground.dart';

/// XChaCha20-Poly1305 under a key the developer can see, swap and misuse.
final class SymmetricPlayground extends Playground {
  SymmetricPlayground(this._lib) {
    _key.text = SymmetricKey.generate(_lib).hex;
  }

  final CipherBird _lib;
  final _key = PlayField('Key (hex, 32 bytes)');
  final _plain = PlayField('Plaintext', text: 'meet at dawn', lines: 2);
  final _aad = PlayField('Associated data', text: 'invoice 42');
  final _cipher = PlayField('Ciphertext (base64, editable)', lines: 3);

  SymmetricKey get _k => SymmetricKey.fromHex(_key.text, _lib);

  @override
  String get title => 'Symmetric encryption';

  @override
  String get blurb =>
      'Encrypt, edit the ciphertext or the associated data, and watch '
      'decryption refuse anything that was touched.';

  @override
  List<PlayField> get fields => [_key, _plain, _aad, _cipher];

  @override
  List<PlayAction> get actions => [
    PlayAction('New key', () async {
      _key.text = SymmetricKey.generate(_lib).hex;
      say('fresh 32-byte key');
    }),
    PlayAction(
      'Encrypt',
      () async => attempt('encrypt', () async {
        _cipher.text = _k.encryptText(_plain.text, aad: _aad.text);
        say('encrypted: ${Playground.brief(_cipher.text)}');
      }),
    ),
    PlayAction(
      'Decrypt',
      () async => attempt('decrypt', () async {
        say('decrypted: ${_k.decryptText(_cipher.text, aad: _aad.text)}');
      }),
    ),
    PlayAction('Flip one bit', () async {
      final units = _cipher.text.codeUnits.toList();
      if (units.length < 8) {
        say('nothing to flip');
        return;
      }
      final i = units.length ~/ 2;
      units[i] = units[i] == 65 ? 66 : 65;
      _cipher.text = String.fromCharCodes(units);
      say('changed one character in the middle of the ciphertext');
    }),
  ];
}
