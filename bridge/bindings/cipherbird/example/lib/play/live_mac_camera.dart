part of 'live_playground.dart';

/// The cameras that deliver frames rather than a platform preview: the
/// example's own AVFoundation grabber on macOS and getUserMedia in the
/// browser. The luma plane of each frame is one chunk, as on a phone, and
/// a colour copy of each frame is drawn as the preview.
extension on LivePlayground {
  bool get _onMac => kIsWeb || Platform.isMacOS;

  FrameCamera _frameCamera() => kIsWeb ? BrowserCamera() : const MacCamera();

  Future<void> startMacCamera() => attempt('camera', () async {
    if (_macFrames != null) {
      say('the camera is already running');
      return;
    }
    final camera = _frameCamera();
    _camOnFrames = camera;
    final (int, int) size;
    try {
      size = await camera.start(_resolution.value);
    } on PlatformException catch (e) {
      _camOnFrames = null;
      say(
        'camera: ${e.message}; allow the camera for this app in the system '
        'settings, or open the app on its own rather than from a shell',
      );
      return;
    }
    final (w, h) = size;
    var drawing = false;
    _macFrames = camera.frames.listen((f) {
      _fed(
        _source().feed(f.luma, sourceId: 1),
        'camera, ${f.width}x${f.height}, ${f.luma.length} bytes a frame',
      );
      if (!drawing) {
        drawing = true;
        unawaited(_drawLuma(f).whenComplete(() => drawing = false));
      }
    }, onError: (Object e) => say('camera: ${Playground.reason(e)}'));
    say(
      'camera streaming at ${w}x$h, delivered subsampled at up to '
      'fifteen frames a second; the luma plane of each frame is one chunk. Move '
      'something in front of it: a still scene has blank runs the policy '
      'refuses',
    );
  });

  Future<void> _drawLuma(LumaFrame f) async {
    final done = Completer<ui.Image>();
    ui.decodeImageFromPixels(
      f.rgba,
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
    final cam = _camOnFrames;
    _camOnFrames = null;
    if (cam != null) {
      await attempt('stop camera', cam.stop);
    }
    _macFrame.value = null;
    say('camera stopped after ${meter.value.chunks} chunks');
    refresh();
  }
}
