import 'package:cipherbird/src/hardware/hardware_backend.dart';
import 'package:cipherbird/src/hardware/unsupported_backend.dart';

/// The browser has no key module.
HardwareBackend createPlatformBackend() => const UnsupportedBackend('the web');
