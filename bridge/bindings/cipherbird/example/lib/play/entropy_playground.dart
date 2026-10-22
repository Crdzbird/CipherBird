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
import 'package:cipherbird_example/util/bytes.dart';

part 'entropy_harvest.dart';
part 'entropy_pick.dart';
part 'entropy_use.dart';

/// Turn a photo or a sound into keys: judge the source first, harvest it
/// under a policy, then derive keys, seed generators and seal with it.
final class EntropyPlayground extends Playground {
  EntropyPlayground(this._lib) : _recipe = RecipeOptions(_lib);

  final CipherBird _lib;
  final RecipeOptions _recipe;
  late final PlayFiles _files = PlayFiles('entropy');
  PickedMedia? _picked;

  final _source = PlayChoice('Source', [
    'photo PPM',
    'flat colour PPM (weak)',
    'noise PPM',
    'tone WAV',
    'picked file',
  ]);
  final _mode = PlayChoice('Harvest', [
    'fresh (LavaRand: the file mixed with system randomness)',
    'deterministic (the file alone, reproducible)',
  ]);
  final _rct = PlayChoice('Repetition-count test', [
    'required',
    'reported only',
  ]);
  final _floor = PlayField(
    'Policy floor, min-entropy bits per byte',
    text: '1.0',
  );
  final _message = PlayField('Message to seal', text: 'the vault code is 4471');
  final _aad = PlayField('Associated data', text: 'ctx');
  final _picture = PlayPicture('source');

  @override
  String get title => 'LavaRand media entropy';

  @override
  String get blurb =>
      'Make a source or pick any file on this device, read its health '
      'report, harvest it under the policy '
      'you set (lower the floor or drop the test to accept the flat image), '
      'then use what came out: derived keys, a DRBG, Fortuna, a file-keyed '
      'seal and a custom recipe keyed by the file.';

  @override
  List<PlayField> get fields => [_floor, _message, _aad];

  @override
  List<PlayChoice> get choices => [_source, _mode, _rct, ..._recipe.choices];

  @override
  List<PlayPicture> get pictures => [_picture];

  @override
  List<PlayAction> get actions => [
    PlayAction('Pick a file', pickFile),
    PlayAction('New source', newSource),
    PlayAction('Assess health', assess),
    PlayAction('Harvest', harvest),
    PlayAction('Harvest twice', harvestTwice),
    PlayAction('Derive keys', deriveKeys),
    PlayAction('Seal with the file', sealWithFile),
    PlayAction('Seed a DRBG', seedDrbg),
    PlayAction('Feed Fortuna', feedFortuna),
    PlayAction('Recipe keyed by the file', recipeWithFile),
  ];
}
