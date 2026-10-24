import 'package:cipherbird/src/hardware/hardware_backend.dart';
import 'package:cipherbird/src/hardware/web/web_key_backend.dart';

/// In the browser the key module is a non-extractable WebCrypto key kept in
/// IndexedDB; `backing` reports it as the browser, not hardware.
HardwareBackend createPlatformBackend() => const WebKeyBackend();
