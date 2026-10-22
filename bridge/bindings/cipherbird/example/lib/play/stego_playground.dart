import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/media/carrier_audio.dart';
import 'package:cipherbird_example/play/media/carrier_images.dart';
import 'package:cipherbird_example/play/media/file_pick.dart';
import 'package:cipherbird_example/play/media/picked_media.dart';
import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_choice.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/play_files.dart';
import 'package:cipherbird_example/play/play_picture.dart';
import 'package:cipherbird_example/play/playground.dart';
import 'package:cipherbird_example/play/recipe_options.dart';
import 'package:cipherbird_example/play/stego_options.dart';
import 'package:cipherbird_example/util/bytes.dart';

part 'stego_checks.dart';
part 'stego_hide.dart';
part 'stego_pick.dart';
part 'stego_reveal.dart';

/// Hide a secret in a generated photo or sound, seven different ways, then
/// try to get it back with the right key, the wrong key and a damaged file.
final class StegoPlayground extends Playground {
  StegoPlayground(this._lib) : _recipe = RecipeOptions(_lib) {
    _key.text = SymmetricKey.generate(_lib).hex;
  }

  final CipherBird _lib;
  final RecipeOptions _recipe;
  late final PlayFiles _files = PlayFiles('stego');
  late final KeyPairResult _bob = _lib.hpkeKeygen();
  late final KeyPairResult _carol = _lib.hpkeKeygen();
  late final Uint8List _oprfSeed = _lib.randomBytes(32);
  Uint8List _enc = Uint8List(0);
  PickedMedia? _picked;

  final _carrier = PlayChoice('Carrier', stegoCarriers);
  final _mode = PlayChoice('Mode', stegoModes);
  final _recipeKey = PlayChoice('Recipe key', stegoRecipeKeys);
  final _secret = PlayField(
    'Secret',
    text: 'meet at the old bridge, bring the ledger',
    lines: 2,
  );
  final _key = PlayField('Key (hex, 32 bytes)');
  final _passphrase = PlayField(
    'Passphrase',
    text: 'correct horse battery staple',
  );
  final _aad = PlayField('Associated data', text: 'ctx');
  final _cover = PlayPicture('cover');
  final _hidden = PlayPicture('with the secret');

  @override
  String get title => 'Steganography';

  @override
  String get blurb =>
      'Generate a carrier or pick any image, sound or video on this device, '
      'choose a mode, hide the secret and look at the '
      'result: the picture is unchanged to the eye, the log counts the bytes '
      'that moved. Reveal with the right key, then the wrong one, then '
      'damage the file and see what survives.';

  @override
  List<PlayField> get fields => [_secret, _key, _passphrase, _aad];

  @override
  List<PlayChoice> get choices => [
    _carrier,
    _mode,
    _recipeKey,
    ..._recipe.choices,
  ];

  @override
  List<PlayPicture> get pictures => [_cover, _hidden];

  @override
  List<PlayAction> get actions => [
    PlayAction('Pick a file', pickFile),
    PlayAction('New carrier', newCarrier),
    PlayAction('Hide', hide),
    PlayAction('Reveal', reveal),
    PlayAction('Reveal with the wrong key', revealWrong),
    PlayAction('Inspect', inspect),
    PlayAction('Detect hidden data', detectHidden),
    PlayAction('Damage lightly', () => damage(heavy: false)),
    PlayAction('Damage heavily', () => damage(heavy: true)),
    PlayAction('Describe recipe', describeRecipe),
  ];
}
