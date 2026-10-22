import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';
import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/playground.dart';
import 'package:cipherbird_example/util/bytes.dart';

/// The validated module of this device, operation by operation.
final class FipsPlayground extends Playground {
  FipsPlayground(CipherBird lib);

  final _fips = DeviceFips.platform();
  KeyPairResult? _p256;
  final _text = PlayField('Text', text: 'cardholder data', lines: 2);
  final _key = PlayField('AES-256 key (hex)');
  final _wire = PlayField('AES-GCM wire (hex, editable)', lines: 3);
  final _sig = PlayField('ECDSA signature (hex)', lines: 2);

  @override
  String get title => 'Validated module';

  @override
  String get blurb =>
      'Every button runs inside the module the platform validated: Apple '
      'corecrypto, the Android providers, or the OpenSSL FIPS Provider.';

  @override
  List<PlayField> get fields => [_text, _key, _wire, _sig];

  @override
  List<PlayAction> get actions => [
    PlayAction(
      'Which module',
      () async => attempt('module', () async {
        final i = await _fips.module();
        say('${i.module} on ${i.platform} ${i.providers}');
      }),
    ),
    PlayAction(
      'New AES key',
      () async => attempt('random', () async {
        _key.text = hexOf(await _fips.random(32));
        say('32 bytes from the module DRBG');
      }),
    ),
    PlayAction(
      'AES-GCM encrypt',
      () async => attempt('encrypt', () async {
        final w = await _fips.aesGcmEncrypt(
          bytesOfHex(_key.text),
          ascii(_text.text),
        );
        _wire.text = hexOf(w);
        say('nonce(12) | ct | tag(16): ${w.length} bytes');
      }),
    ),
    PlayAction(
      'AES-GCM decrypt',
      () async => attempt('decrypt', () async {
        final pt = await _fips.aesGcmDecrypt(
          bytesOfHex(_key.text),
          bytesOfHex(_wire.text),
        );
        say('decrypted: ${String.fromCharCodes(pt)}');
      }),
    ),
    PlayAction(
      'P-256 key',
      () async => attempt('keygen', () async {
        _p256 = await _fips.p256Keygen();
        say('P-256 public key ${hexOf(_p256!.publicKey).substring(0, 20)}...');
      }),
    ),
    PlayAction(
      'ECDSA sign',
      () async => attempt('sign', () async {
        final kp = _p256 ?? (_p256 = await _fips.p256Keygen());
        _sig.text = hexOf(
          await _fips.p256Sign(kp.secretKey, ascii(_text.text)),
        );
        say('DER signature ${_sig.text.length ~/ 2} bytes');
      }),
    ),
  ];
}
