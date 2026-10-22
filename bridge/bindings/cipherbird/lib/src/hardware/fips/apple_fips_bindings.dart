import 'dart:ffi';

import 'package:cipherbird/src/hardware/fips/apple_fips_key_types.dart';
import 'package:cipherbird/src/hardware/fips/apple_fips_types.dart';

/// The `@_cdecl` functions of `FipsCrypto.swift`, resolved once from the
/// host process.
final class AppleFipsBindings {
  AppleFipsBindings._(DynamicLibrary lib)
    : module = lib.lookupFunction<ModuleC, ModuleD>('cipherbird_fips_module'),
      digest = lib.lookupFunction<DigestC, DigestD>('cipherbird_fips_digest'),
      hmac = lib.lookupFunction<HmacC, HmacD>('cipherbird_fips_hmac'),
      hkdf = lib.lookupFunction<HkdfC, HkdfD>('cipherbird_fips_hkdf'),
      pbkdf2 = lib.lookupFunction<Pbkdf2C, Pbkdf2D>('cipherbird_fips_pbkdf2'),
      random = lib.lookupFunction<RandomC, RandomD>('cipherbird_fips_random'),
      aesGcmEncrypt = lib.lookupFunction<ThreeBufC, ThreeBufD>(
        'cipherbird_fips_aes_gcm_encrypt',
      ),
      aesGcmDecrypt = lib.lookupFunction<ThreeBufC, ThreeBufD>(
        'cipherbird_fips_aes_gcm_decrypt',
      ),
      p256Keygen = lib.lookupFunction<KeygenC, KeygenD>(
        'cipherbird_fips_p256_keygen',
      ),
      p256Ecdh = lib.lookupFunction<TwoBufC, TwoBufD>(
        'cipherbird_fips_p256_ecdh',
      ),
      p256Sign = lib.lookupFunction<TwoBufC, TwoBufD>(
        'cipherbird_fips_p256_sign',
      ),
      p256Verify = lib.lookupFunction<VerifyC, VerifyD>(
        'cipherbird_fips_p256_verify',
      ),
      p256PublicKey = lib.lookupFunction<OneBufC, OneBufD>(
        'cipherbird_fips_p256_public_key',
      ),
      free = lib.lookupFunction<FreeC, FreeD>('cipherbird_fips_free');

  /// Resolves against the running process (the plugin is linked in).
  factory AppleFipsBindings.process() =>
      AppleFipsBindings._(DynamicLibrary.process());

  final ModuleD module;
  final DigestD digest;
  final HmacD hmac;
  final HkdfD hkdf;
  final Pbkdf2D pbkdf2;
  final RandomD random;
  final ThreeBufD aesGcmEncrypt;
  final ThreeBufD aesGcmDecrypt;
  final KeygenD p256Keygen;
  final TwoBufD p256Ecdh;
  final TwoBufD p256Sign;
  final VerifyD p256Verify;
  final OneBufD p256PublicKey;
  final FreeD free;
}
