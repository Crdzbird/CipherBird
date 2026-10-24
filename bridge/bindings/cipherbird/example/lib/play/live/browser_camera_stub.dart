import 'package:cipherbird_example/play/live/frame_camera.dart';
import 'package:cipherbird_example/play/live/luma_frame.dart';

/// Placeholder outside the browser; never constructed there.
final class BrowserCamera implements FrameCamera {
  const BrowserCamera();

  @override
  Future<(int, int)> start(String preset) =>
      throw UnsupportedError('the browser camera exists only on the web');

  @override
  Stream<LumaFrame> get frames => const Stream.empty();

  @override
  Future<void> stop() async {}
}
