import 'dart:io';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/android_fips_backend.dart';
import 'package:cipherbird/src/hardware/fips/apple_fips_backend.dart';
import 'package:cipherbird/src/hardware/fips/fips_backend.dart';
import 'package:cipherbird/src/hardware/fips/native_fips_backend.dart';
import 'package:cipherbird/src/hardware/fips/unsupported_fips_backend.dart';

/// The validated module for this platform: Apple corecrypto on iOS and
/// macOS, the Android platform providers on Android, the OpenSSL FIPS
/// Provider when the loaded engine is the fips profile, nothing elsewhere.
FipsBackend createPlatformFipsBackend({CipherBird? engine}) {
  if (Platform.isIOS || Platform.isMacOS) {
    return const AppleFipsBackend();
  }
  if (Platform.isAndroid) {
    return const AndroidFipsBackend();
  }
  final e = engine ?? CipherBird.instance;
  if (e.fipsAvailable) {
    return NativeFipsBackend(e);
  }
  return UnsupportedFipsBackend(Platform.operatingSystem);
}
