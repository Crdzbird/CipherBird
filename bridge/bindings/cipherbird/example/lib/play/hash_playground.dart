import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';
import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/playground.dart';
import 'package:cipherbird_example/util/bytes.dart';

/// Digests and MACs over whatever the developer types.
final class HashPlayground extends Playground {
  HashPlayground(this._lib);

  final CipherBird _lib;
  final _text = PlayField('Text', text: 'abc', lines: 3);
  final _key = PlayField(
    'HMAC key (text)',
    text: 'a key of at least fourteen bytes',
  );

  @override
  String get title => 'Hashes and MACs';

  @override
  String get blurb =>
      'Type anything, hash it with the engine or with the validated module '
      'of this device, and compare.';

  @override
  List<PlayField> get fields => [_text, _key];

  @override
  List<PlayAction> get actions => [
    PlayAction(
      'SHA-256',
      () async => say('SHA-256  ${_lib.easy.sha256Hex(_text.text)}'),
    ),
    PlayAction(
      'SHA-512',
      () async => say('SHA-512  ${hexOf(_lib.sha512(ascii(_text.text)))}'),
    ),
    PlayAction(
      'BLAKE2b',
      () async => say('BLAKE2b  ${hexOf(_lib.blake2b(ascii(_text.text)))}'),
    ),
    PlayAction(
      'HMAC-SHA256',
      () async => attempt('HMAC', () async {
        say(
          'HMAC     ${hexOf(_lib.hmacSha256(ascii(_text.text), ascii(_key.text)))}',
        );
      }),
    ),
    PlayAction(
      'SHA-256 via validated module',
      () async => attempt('module', () async {
        final fips = DeviceFips.platform();
        final info = await fips.module();
        say(
          'module   ${hexOf(await fips.digest(FipsHash.sha256, ascii(_text.text)))} (${info.module})',
        );
      }),
    ),
    PlayAction(
      'HMAC via validated module',
      () async => attempt('module', () async {
        final tag = await DeviceFips.platform().hmac(
          FipsHash.sha256,
          ascii(_key.text),
          ascii(_text.text),
        );
        say('module   ${hexOf(tag)}');
      }),
    ),
  ];
}
