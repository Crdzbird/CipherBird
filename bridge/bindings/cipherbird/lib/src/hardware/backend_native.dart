import 'dart:io';

import 'package:cipherbird/src/hardware/android_backend.dart';
import 'package:cipherbird/src/hardware/apple_backend.dart';
import 'package:cipherbird/src/hardware/hardware_backend.dart';
import 'package:cipherbird/src/hardware/unsupported_backend.dart';

/// The key module for this platform: Secure Enclave on iOS and macOS,
/// Android Keystore on Android, nothing elsewhere.
HardwareBackend createPlatformBackend() {
  if (Platform.isIOS || Platform.isMacOS) {
    return const AppleBackend();
  }
  if (Platform.isAndroid) {
    return const AndroidBackend();
  }
  return UnsupportedBackend(Platform.operatingSystem);
}
