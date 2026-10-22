part of 'live_playground.dart';

/// The macOS camera through the example's own AVFoundation grabber: the
/// luma plane of each frame is one chunk, as on a phone, and every sixth
/// frame is drawn as the preview.
extension on LivePlayground {
  bool get _onMac => !kIsWeb && Platform.isMacOS;

  Future<void> startMacCamera() => attempt('camera', () async {
    if (_macFrames != null) {
      say('the camera is already running');
      return;
    }
    const camera = MacCamera();
    final (w, h) = await camera.start(_resolution.value);
    var n = 0;
    _macFrames = camera.frames.listen((f) {
      _fed(
        _source().feed(f.luma, sourceId: 1),
        'camera, ${f.width}x${f.height}, ${f.luma.length} bytes a frame',
      );
      if (n++ % 6 == 0) {
        unawaited(_drawLuma(f));
      }
    }, onError: (Object e) => say('camera: ${Playground.reason(e)}'));
    say(
      'camera streaming at ${w}x$h, delivered subsampled at up to ten '
      'frames a second; the luma plane of each frame is one chunk. Move '
      'something in front of it: a still scene has blank runs the policy '
      'refuses',
    );
  });

  Future<void> _drawLuma(MacFrame f) async {
    final rgba = Uint8List(f.luma.length * 4);
    for (var i = 0; i < f.luma.length; i++) {
      rgba[i * 4] = f.luma[i];
      rgba[i * 4 + 1] = f.luma[i];
      rgba[i * 4 + 2] = f.luma[i];
      rgba[i * 4 + 3] = 255;
    }
    final done = Completer<ui.Image>();
    ui.decodeImageFromPixels(
      rgba,
      f.width,
      f.height,
      ui.PixelFormat.rgba8888,
      done.complete,
    );
    _macFrame.value = await done.future;
  }

  Future<void> stopMacCamera() async {
    final s = _macFrames;
    _macFrames = null;
    if (s == null) {
      return;
    }
    await s.cancel();
    await attempt('stop camera', () => const MacCamera().stop());
    _macFrame.value = null;
    say('camera stopped after ${meter.value.chunks} chunks');
    refresh();
  }
}
