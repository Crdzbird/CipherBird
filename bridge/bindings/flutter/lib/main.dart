import 'dart:io';
import 'package:flutter/material.dart';
import 'app.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();

  // On mobile the native code is bundled in the app (iOS: embedded
  // xcframework, Android: jniLibs), so there is no host path — load the
  // platform default. On desktop, resolve a dev path: env var > build output.
  final isMobile = Platform.isIOS || Platform.isAndroid;
  final String? libPath = isMobile
      ? null
      : (Platform.environment['CRYPTOLIB_PATH'] ??
          '${Directory.current.parent.parent.path}/build/release/libcryptolib_c.dylib');

  runApp(CryptoLibApp(initialLibPath: libPath));
}
