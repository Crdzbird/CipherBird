import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/fips_exception.dart';
import 'package:cipherbird/src/hardware/fips/fips_module_info.dart';
import 'package:flutter/services.dart';

/// The "cipherbird/fips" method channel served by `CipherbirdFipsChannel.kt`.
final class AndroidFipsChannel {
  const AndroidFipsChannel._();

  static const MethodChannel _channel = MethodChannel('cipherbird/fips');

  static Future<T> call<T>(String method, Map<String, Object?> args) async {
    try {
      final value = await _channel.invokeMethod<T>(method, args);
      if (value == null) {
        throw const FipsException('failed', 'empty platform reply');
      }
      return value;
    } on PlatformException catch (e) {
      throw FipsException(e.code, e.message ?? e.code);
    }
  }

  /// Channel replies arrive as unmodifiable lists; secrets must be wipeable.
  static Future<Uint8List> bytes(
    String method,
    Map<String, Object?> args,
  ) async => Uint8List.fromList(await call<Uint8List>(method, args));

  static Future<FipsModuleInfo> module() async {
    final m = await call<Map<Object?, Object?>>('module', {});
    final providers = (m['providers']! as Map<Object?, Object?>).map(
      (k, v) => MapEntry(k! as String, v! as String),
    );
    return FipsModuleInfo(
      module: m['module']! as String,
      platform: m['platform']! as String,
      providers: providers,
      hkdfComposed: m['hkdfComposed'] == true,
      pbkdf2Composed: m['pbkdf2Composed'] == true,
    );
  }

  static Future<KeyPairResult> keyPair(String method) async {
    final m = await call<Map<Object?, Object?>>(method, {});
    return KeyPairResult(
      publicKey: Uint8List.fromList(m['publicKey']! as Uint8List),
      secretKey: Uint8List.fromList(m['privateKey']! as Uint8List),
    );
  }

  static Future<Uint8List> hkdf(
    FipsHash h,
    Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    int n,
  ) => bytes('hkdf', {
    'hash': h.value,
    'ikm': ikm,
    'salt': salt,
    'info': info,
    'count': n,
  });

  static Future<Uint8List> pbkdf2(
    FipsHash h,
    Uint8List pw,
    Uint8List salt,
    int iters,
    int n,
  ) => bytes('pbkdf2', {
    'hash': h.value,
    'password': pw,
    'salt': salt,
    'iterations': iters,
    'count': n,
  });
}
