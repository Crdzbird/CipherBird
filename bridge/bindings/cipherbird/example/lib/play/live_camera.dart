part of 'live_playground.dart';

extension on LivePlayground {
  LiveEntropy _source() {
    final existing = _live;
    if (existing != null) {
      return existing;
    }
    final created = _lib.liveEntropy(
      minBitsPerByte: double.parse(_floor.text),
      requireRct: _rct.picked('required'),
      minCreditedBits: double.parse(_credit.text),
    );
    _live = created;
    return created;
  }

  Future<void> newSource() => attempt('new source', () async {
    stopStream();
    _live?.close();
    _live = null;
    _key = null;
    _keyHex.text = '';
    _cipher.text = '';
    meter.value = const LiveMeterState();
    _source();
    say(
      'new source: floor ${_floor.text} bits/byte, repetition-count test '
      '${_rct.value}, seeds after ${_credit.text} credited bits; now feed it',
    );
  });

  ResolutionPreset get _preset => switch (_resolution.value) {
    'high' => ResolutionPreset.high,
    'medium' => ResolutionPreset.medium,
    _ => ResolutionPreset.low,
  };

  Future<void> startCamera() => attempt('camera', () async {
    if (_camera != null) {
      say('the camera is already running');
      return;
    }
    final List<CameraDescription> cameras;
    try {
      cameras = await availableCameras();
    } on MissingPluginException {
      say('camera: unsupported on this platform, use Stream instead');
      return;
    }
    if (cameras.isEmpty) {
      say('camera: unsupported here, no camera was found; use Stream instead');
      return;
    }
    final c = CameraController(
      cameras.first,
      _preset,
      enableAudio: false,
      imageFormatGroup: ImageFormatGroup.yuv420,
    );
    await c.initialize();
    _camera = c;
    await c.startImageStream(_onFrame);
    say(
      'camera ${cameras.first.name} streaming at ${_resolution.value}; each '
      'frame\'s luma plane is one chunk. Move the phone: a still scene has '
      'blank runs the policy refuses',
    );
    refresh();
  });

  void _onFrame(CameraImage image) {
    final plane = image.planes.first.bytes;
    _fed(
      _source().feed(plane, sourceId: 1),
      'camera, ${plane.length} bytes a frame',
    );
  }

  Future<void> stopCamera() async {
    final c = _camera;
    _camera = null;
    if (c == null) {
      return;
    }
    await attempt('stop camera', () async {
      if (c.value.isStreamingImages) {
        await c.stopImageStream();
      }
      await c.dispose();
      say('camera stopped after ${meter.value.chunks} chunks');
      refresh();
    });
  }
}
