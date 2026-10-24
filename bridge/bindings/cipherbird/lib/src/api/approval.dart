part of '../cipher_bird.dart';

/// The approval boundary of this build (assessment r2, M3). In a browser
/// the engine's memory is readable by every script on the page and the
/// worker cannot wipe JavaScript strings, so the web build is approved for
/// [ProtectedDataClass.ephemeral] only; native builds are approved for all.
extension CipherBirdApproval on CipherBird {
  /// Whether this build runs in a browser.
  bool get isWebBuild => platformIsWeb;

  /// Whether this build is approved to protect [dataClass].
  bool approvedFor(ProtectedDataClass dataClass) => switch (dataClass) {
    ProtectedDataClass.ephemeral => true,
    ProtectedDataClass.longLivedKeys => !platformIsWeb || engineWorkerOnly,
    ProtectedDataClass.cardData => !platformIsWeb,
  };

  /// Throws [UnsupportedError] unless this build is approved for
  /// [dataClass]; call it once at startup for the most sensitive class the
  /// app handles.
  void requireApprovedFor(ProtectedDataClass dataClass) {
    if (approvedFor(dataClass)) {
      return;
    }
    throw UnsupportedError(
      'cipherbird: the web build is not approved for ${dataClass.name}; '
      'long-lived keys need preload(workerOnly: true) in the browser and '
      'card data a native build',
    );
  }
}
