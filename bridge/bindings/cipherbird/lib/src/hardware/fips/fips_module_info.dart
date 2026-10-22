/// Which validated module performs the operations on this platform.
final class FipsModuleInfo {
  const FipsModuleInfo({
    required this.module,
    required this.platform,
    this.providers = const {},
    this.hkdfComposed = false,
    this.pbkdf2Composed = false,
  });

  /// The module, as the platform describes it: Apple corecrypto behind
  /// CryptoKit, the Android platform providers, or the OpenSSL FIPS
  /// Provider inside the engine.
  final String module;

  /// Operating system and version, for mapping to a CMVP certificate.
  final String platform;

  /// Provider that served each algorithm family, where the platform
  /// reports one (Android).
  final Map<String, String> providers;

  /// True when the RFC 5869 arithmetic of HKDF runs in the app process
  /// around HMAC calls inside the module (Android below API 35).
  final bool hkdfComposed;

  /// True when the RFC 8018 iteration loop of PBKDF2 runs in the app
  /// process around HMAC calls inside the module (Android, whose own
  /// PBKDF2 is served by a software provider).
  final bool pbkdf2Composed;
}
