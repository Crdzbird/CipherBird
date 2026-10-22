import 'package:flutter/services.dart';

/// The example's own macOS camera: an AVFoundation session in the Runner
/// that sends the luma plane of every frame over an event channel.
final class MacCamera {
  const MacCamera();

  static const _methods = MethodChannel('cipherbird_example/live_camera');
  static const _frames = EventChannel('cipherbird_example/live_camera/frames');

  /// Starts capturing at [preset] (low, medium or high) and returns the
  /// frame size; asks for camera access the first time.
  Future<(int, int)> start(String preset) async {
    final r = await _methods.invokeMapMethod<String, Object?>('start', {
      'preset': preset,
    });
    return (r?['width']! as int, r?['height']! as int);
  }

  /// One event per frame: width, height, the luma plane and a colour copy.
  Stream<MacFrame> get frames => _frames.receiveBroadcastStream().map((e) {
    final m = e as Map<Object?, Object?>;
    return MacFrame(
      m['width']! as int,
      m['height']! as int,
      m['luma']! as Uint8List,
      m['rgba']! as Uint8List,
    );
  });

  Future<void> stop() => _methods.invokeMethod<void>('stop');
}

/// One captured frame: the luma plane that is assessed and a colour copy
/// for the preview.
final class MacFrame {
  const MacFrame(this.width, this.height, this.luma, this.rgba);

  final int width;
  final int height;
  final Uint8List luma;
  final Uint8List rgba;
}
