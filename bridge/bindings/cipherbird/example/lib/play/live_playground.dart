import 'dart:async';

import 'package:camera/camera.dart';
import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/media/carrier_images.dart';
import 'package:cipherbird_example/play/media/file_pick.dart';
import 'package:cipherbird_example/play/media/picked_media.dart';
import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_choice.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/playground.dart';
import 'package:cipherbird_example/util/bytes.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

part 'live_camera.dart';
part 'live_stream.dart';

/// Randomness that never stops: camera frames or a streamed file feed a
/// policy-gated source that seeds a DRBG and keeps reseeding it.
final class LivePlayground extends Playground {
  LivePlayground(this._lib);

  final CipherBird _lib;
  LiveEntropy? _live;
  CameraController? _camera;
  Timer? _stream;
  PickedMedia? _picked;
  int _framesFed = 0;

  final _floor = PlayField(
    'Policy floor, min-entropy bits per byte',
    text: '1.0',
  );
  final _credit = PlayField(
    'Credit needed to seed and to reseed, bits',
    text: '256',
  );
  final _status = PlayField('Live status', lines: 4);
  final _rct = PlayChoice('Repetition-count test', [
    'required',
    'reported only',
  ]);
  final _resolution = PlayChoice('Camera resolution', [
    'low',
    'medium',
    'high',
  ]);

  @override
  String get title => 'Live entropy';

  @override
  String get blurb =>
      'Point the camera at anything that moves, or stream a file. Every '
      'frame is assessed, credited when it passes the policy, and the '
      'status shows the credit flowing in. Generate draws from the DRBG the '
      'stream keeps reseeding; it refuses until enough credit has arrived.';

  @override
  List<PlayField> get fields => [_floor, _credit, _status];

  @override
  List<PlayChoice> get choices => [_rct, _resolution];

  @override
  Widget? get preview {
    final c = _camera;
    return c == null || !c.value.isInitialized ? null : CameraPreview(c);
  }

  @override
  List<PlayAction> get actions => [
    PlayAction('New source', newSource),
    PlayAction('Start camera', startCamera),
    PlayAction('Stop camera', stopCamera),
    PlayAction('Pick a file to stream', pickFile),
    PlayAction('Stream', startStream),
    PlayAction('Stop stream', () async => stopStream()),
    PlayAction('Generate 32 bytes', generate),
    PlayAction('Status', showStatus),
  ];

  @override
  void dispose() {
    stopStream();
    unawaited(stopCamera());
    _live?.close();
    super.dispose();
  }
}
