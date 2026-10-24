import 'dart:async';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:camera/camera.dart';
import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/live/live_meter.dart';
import 'package:cipherbird_example/play/live/live_meter_state.dart';
import 'package:cipherbird_example/play/live/browser_camera.dart';
import 'package:cipherbird_example/play/live/frame_camera.dart';
import 'package:cipherbird_example/play/live/luma_frame.dart';
import 'package:cipherbird_example/play/live/mac_camera.dart';
import 'package:cipherbird_example/play/media/carrier_images.dart';
import 'package:cipherbird_example/play/media/file_pick.dart';
import 'package:cipherbird_example/play/media/picked_media.dart';
import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_choice.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/playground.dart';
import 'package:cipherbird_example/util/bytes.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

part 'live_camera.dart';
part 'live_crypto.dart';
part 'live_mac_camera.dart';
part 'live_stream.dart';

/// Randomness that never stops, in four visible steps: a stream feeds the
/// source, every chunk is assessed and credited or refused, the credit
/// seeds a DRBG, and a key drawn from it encrypts a message.
final class LivePlayground extends Playground {
  LivePlayground(this._lib);

  final CipherBird _lib;
  LiveEntropy? _live;
  CameraController? _camera;
  StreamSubscription<LumaFrame>? _macFrames;
  FrameCamera? _camOnFrames;
  final _macFrame = ValueNotifier<ui.Image?>(null);
  Timer? _stream;
  PickedMedia? _picked;
  SymmetricKey? _key;
  final meter = ValueNotifier<LiveMeterState>(const LiveMeterState());

  final _floor = PlayField('1. Policy floor, bits per byte', text: '1.0');
  final _credit = PlayField('2. Credit to seed and reseed, bits', text: '256');
  final _message = PlayField('3. Message', text: 'pier 9 at dawn', lines: 2);
  final _keyHex = PlayField('Key drawn from the stream (hex, 32 bytes)');
  final _cipher = PlayField('Ciphertext (base64)', lines: 3);
  final _rct = PlayChoice('Repetition-count', ['required', 'reported only']);
  final _refresh = PlayChoice('Key refresh', liveRefreshModes);
  final _resolution = PlayChoice('Camera resolution', [
    'low',
    'medium',
    'high',
  ]);

  @override
  String get title => 'Live entropy';

  @override
  String get blurb =>
      'Start camera, or pick any file and it streams at once; the meter '
      'draws every chunk. The credit fills until the generator seeds, then '
      'a key is drawn and the message re-encrypted on every credited chunk, '
      'so the ciphertext follows what the camera or the file delivers. Draw '
      'key and Encrypt do the same by hand; Decrypt opens the last one.';

  @override
  List<PlayField> get fields => [_floor, _credit, _message, _keyHex, _cipher];

  @override
  List<PlayChoice> get choices => [_refresh, _rct, _resolution];

  @override
  Widget? get preview => previewOf();

  @override
  List<PlayAction> get actions => [
    PlayAction('New source', newSource),
    PlayAction('Start camera', startCamera),
    PlayAction('Stop camera', stopCamera),
    PlayAction('Pick a file to stream', pickFile),
    PlayAction('Stream', startStream),
    PlayAction('Stop stream', () async => stopStream()),
    PlayAction('Draw key', drawKey),
    PlayAction('Encrypt', encrypt),
    PlayAction('Decrypt', decrypt),
    PlayAction('Status', showStatus),
  ];

  @override
  void dispose() {
    tearDown();
    super.dispose();
  }
}
