import 'package:cipherbird_example/play/live/luma_frame.dart';

/// A camera that delivers frames as luma planes: the example's own
/// AVFoundation grabber on macOS, getUserMedia in the browser.
abstract interface class FrameCamera {
  /// Starts capturing at [preset] (low, medium or high) and returns the
  /// frame size; asks for camera access the first time.
  Future<(int, int)> start(String preset);

  /// One event per delivered frame.
  Stream<LumaFrame> get frames;

  Future<void> stop();
}
