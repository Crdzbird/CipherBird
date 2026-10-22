part of '../cipher_bird.dart';

/// What cipherbird knows about the FIPS provider in this process.
final class FipsStatus {
  /// The provider is loaded.
  final bool loaded;

  /// Its power-up self tests ran and passed.
  final bool selfTestsPassed;

  /// Default fetches are restricted to fips=yes implementations.
  final bool approvedMode;

  /// Provider name as the module reports it.
  final String providerName;

  /// Provider version as the module reports it.
  final String providerVersion;

  /// Directory the module was loaded from.
  final String moduleDirectory;

  /// OpenSSL config file that activated it.
  final String configFile;

  const FipsStatus({
    required this.loaded,
    required this.selfTestsPassed,
    required this.approvedMode,
    required this.providerName,
    required this.providerVersion,
    required this.moduleDirectory,
    required this.configFile,
  });
}
