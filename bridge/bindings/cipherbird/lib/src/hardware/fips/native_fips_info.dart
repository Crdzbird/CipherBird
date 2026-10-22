import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/fips_exception.dart';
import 'package:cipherbird/src/hardware/fips/fips_module_info.dart';

/// Describes the OpenSSL FIPS Provider loaded by a fips-profile engine.
final class NativeFipsInfo {
  const NativeFipsInfo._();

  static FipsModuleInfo of(CipherBird engine) {
    final s = engine.fipsStatus();
    return FipsModuleInfo(
      module:
          '${s.providerName} ${s.providerVersion} '
          '(OpenSSL FIPS Provider, CMVP #4985)',
      platform: s.moduleDirectory,
    );
  }

  /// Turns an engine exception into a `FipsException`.
  static Future<T> guard<T>(T Function() op) async {
    try {
      return op();
    } on Exception catch (e) {
      throw FipsException('failed', e.toString());
    }
  }

  /// Throws `unsupported` unless [engine] is the fips profile.
  static void require(CipherBird engine) {
    if (!engine.fipsAvailable) {
      throw const FipsException(
        'unsupported',
        'the engine is not the fips profile',
      );
    }
  }
}
