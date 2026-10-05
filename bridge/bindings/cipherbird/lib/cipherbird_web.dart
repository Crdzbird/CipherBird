/// Web registration for the cipherbird plugin. The web implementation is
/// plain Dart over the WebAssembly engine, so registration has nothing to
/// wire; it exists so Flutter lists the web among the supported platforms.
library;

import 'package:flutter_web_plugins/flutter_web_plugins.dart';

/// Registered by the Flutter tool on web builds.
final class CipherBirdWeb {
  /// Nothing to register: the engine loads through `CipherBird.preload()`.
  static void registerWith(Registrar registrar) {}
}
