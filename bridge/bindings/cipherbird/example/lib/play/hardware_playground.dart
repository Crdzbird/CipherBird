import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_hardware.dart';
import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/playground.dart';
import 'package:cipherbird_example/util/bytes.dart';

/// A key inside the Secure Enclave or the Android Keystore.
final class HardwarePlayground extends Playground {
  HardwarePlayground(this._lib);

  final CipherBird _lib;
  HardwareKey? _key;
  final _label = PlayField('Key label', text: 'playground');
  final _secret = PlayField(
    'Secret to wrap (text)',
    text: 'top secret factor 0123456789',
  );
  final _wrapped = PlayField('Wrapped (hex)', lines: 3);

  @override
  String get title => 'Hardware keys';

  @override
  String get blurb =>
      'Create a key that never leaves the device key module, wrap a secret '
      'under it, unwrap it, attest it, delete it.';

  @override
  List<PlayField> get fields => [_label, _secret, _wrapped];

  HardwareKey _need() {
    final k = _key;
    if (k == null) {
      throw StateError('create or open a key first');
    }
    return k;
  }

  @override
  List<PlayAction> get actions => [
    PlayAction(
      'Create',
      () async => attempt('create', () async {
        _key = await HardwareKey.create(_label.text);
        say('created in ${_key!.backing.name}');
      }),
    ),
    PlayAction(
      'Open',
      () async => attempt('open', () async {
        _key = await HardwareKey.open(_label.text);
        say('opened, backing ${_key!.backing.name}');
      }),
    ),
    PlayAction(
      'Wrap',
      () async => attempt('wrap', () async {
        final blob = await _need().wrap(SecretBytes.take(ascii(_secret.text)));
        _wrapped.text = hexOf(blob);
        say('wrapped: ${blob.length} bytes');
      }),
    ),
    PlayAction(
      'Unwrap',
      () async => attempt('unwrap', () async {
        final back = await _need().unwrap(bytesOfHex(_wrapped.text));
        say('unwrapped: ${String.fromCharCodes(back.bytes)}');
        back.wipe();
      }),
    ),
    PlayAction(
      'Attest',
      () async => attempt('attest', () async {
        final att = await _need().attest(_lib.randomBytes(32));
        say('${att.kind.name}: ${att.document.length}-byte document');
      }),
    ),
    PlayAction(
      'Delete',
      () async => attempt('delete', () async {
        await _need().delete();
        _key = null;
        say('deleted');
      }),
    ),
  ];
}
