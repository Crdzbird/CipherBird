/// Web registration for the cipherbird plugin. Flutter calls [CipherBirdWeb.registerWith]
/// before the app's `main`, which is the earliest moment the WebAssembly
/// engine can start downloading; the load it starts is joined later by
/// `CipherBird.ready` and `CipherBird.preload`.
library;

import 'package:cipherbird/cipherbird.dart';
import 'package:flutter_web_plugins/flutter_web_plugins.dart';

/// Registered by the Flutter tool on web builds.
final class CipherBirdWeb {
  /// The engine load started at registration, for callers that want to
  /// observe it directly; `CipherBird.ready` joins the same load.
  static Future<void>? startup;

  /// Starts fetching and compiling the engine so it overlaps Flutter's own
  /// bootstrap instead of following it.
  static void registerWith(Registrar registrar) {
    startup = CipherBird.ready;
  }
}
