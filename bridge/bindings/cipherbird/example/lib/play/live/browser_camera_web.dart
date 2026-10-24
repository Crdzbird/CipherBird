import 'dart:async';
import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cipherbird_example/play/live/frame_camera.dart';
import 'package:cipherbird_example/play/live/luma_frame.dart';
import 'package:web/web.dart' as web;

/// The browser camera: getUserMedia into a detached video element, drawn
/// onto a canvas up to fifteen times a second; the luma of each frame is
/// computed from the pixels and the colour copy is the pixels themselves.
final class BrowserCamera implements FrameCamera {
  BrowserCamera();

  final _video = web.HTMLVideoElement();
  final _canvas = web.HTMLCanvasElement();
  final _out = StreamController<LumaFrame>.broadcast();
  web.MediaStream? _stream;
  Timer? _timer;

  @override
  Future<(int, int)> start(String preset) async {
    final width = preset == 'high'
        ? 640
        : preset == 'medium'
        ? 480
        : 320;
    final stream = await web.window.navigator.mediaDevices
        .getUserMedia(
          web.MediaStreamConstraints(
            video: web.MediaTrackConstraints(width: width.toJS).jsify()!,
            audio: false.toJS,
          ),
        )
        .toDart;
    _stream = stream;
    _video
      ..srcObject = stream
      ..muted = true
      ..autoplay = true;
    await _video.play().toDart;
    final w = _video.videoWidth == 0 ? width : _video.videoWidth;
    final h = _video.videoHeight == 0 ? width * 3 ~/ 4 : _video.videoHeight;
    _canvas
      ..width = w
      ..height = h;
    _timer = Timer.periodic(const Duration(milliseconds: 66), (_) => _grab());
    return (w, h);
  }

  void _grab() {
    final ctx = _canvas.getContext('2d') as web.CanvasRenderingContext2D?;
    if (ctx == null || _video.videoWidth == 0) {
      return;
    }
    final w = _canvas.width;
    final h = _canvas.height;
    ctx.drawImage(_video, 0, 0, w, h);
    final rgba = Uint8List.fromList(ctx.getImageData(0, 0, w, h).data.toDart);
    final luma = Uint8List(w * h);
    for (var i = 0; i < luma.length; i++) {
      final o = i * 4;
      luma[i] = (rgba[o] * 77 + rgba[o + 1] * 150 + rgba[o + 2] * 29) >> 8;
    }
    _out.add(LumaFrame(w, h, luma, rgba));
  }

  @override
  Stream<LumaFrame> get frames => _out.stream;

  @override
  Future<void> stop() async {
    _timer?.cancel();
    _timer = null;
    final tracks = _stream?.getTracks().toDart ?? const [];
    for (final t in tracks) {
      t.stop();
    }
    _stream = null;
    _video.srcObject = null;
  }
}
