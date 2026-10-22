/// Validated-module cryptography for CipherBird: the approved operations
/// (SHA-2, HMAC, HKDF, PBKDF2, DRBG, AES-256-GCM, P-256 ECDH and ECDSA)
/// performed by the module the platform already validated, so a regulated
/// app keeps them inside a CMVP boundary on every platform it ships to.
/// Apple corecrypto behind CryptoKit on iOS and macOS, the Android platform
/// providers on Android, and the OpenSSL FIPS Provider (certificate #4985)
/// when the engine is built as the fips profile. Flutter only; the browser
/// has no validated module.
///
/// ```dart
/// final fips = DeviceFips.platform();
/// final info = await fips.module();
/// final tag = await fips.hmac(FipsHash.sha256, key, message);
/// ```
library;

export 'src/hardware/fips/device_fips.dart';
export 'src/hardware/fips/fips_backend.dart';
export 'src/hardware/fips/fips_exception.dart';
export 'src/hardware/fips/fips_module_info.dart';
export 'src/hardware/fips/unsupported_fips_backend.dart';
