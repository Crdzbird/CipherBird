import 'package:cipherbird_example/play/live/frame_camera.dart';
import 'package:cipherbird_example/play/live/luma_frame.dart';
import 'package:flutter/services.dart';

/// The example's own macOS camera: an AVFoundation session in the Runner
/// that sends the luma plane of every frame over an event channel.
final class MacCamera implements FrameCamera {
  const MacCamera();

  static const _methods = MethodChannel('cipherbird_example/live_camera');
  static const _frames = EventChannel('cipherbird_example/live_camera/frames');

  @override
  Future<(int, int)> start(String preset) async {
    final r = await _methods.invokeMapMethod<String, Object?>('start', {
      'preset': preset,
    });
    return (r?['width']! as int, r?['height']! as int);
  }

  @override
  Stream<LumaFrame> get frames => _frames.receiveBroadcastStream().map((e) {
    final m = e as Map<Object?, Object?>;
    return LumaFrame(
      m['width']! as int,
      m['height']! as int,
      m['luma']! as Uint8List,
      m['rgba']! as Uint8List,
    );
  });

  @override
  Future<void> stop() => _methods.invokeMethod<void>('stop');
}
