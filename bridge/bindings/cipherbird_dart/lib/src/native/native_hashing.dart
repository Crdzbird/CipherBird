part of '../cryptolib.dart';

final class _NativeHashing {
  _NativeHashing(DynamicLibrary lib)
    : blake2b = lib.lookupFunction<_Blake2bC, _Blake2bDart>(
        'cryptolib_blake2b',
      ),
      sha256 = lib.lookupFunction<_Sha256C, _Sha256Dart>('cryptolib_sha256'),
      sha512 = lib.lookupFunction<_Sha512C, _Sha512Dart>('cryptolib_sha512'),
      hmacSha512 = lib.lookupFunction<_HmacSha512C, _HmacSha512Dart>(
        'cryptolib_hmac_sha512',
      ),
      hmacSha512Verify = lib
          .lookupFunction<_HmacSha512VerifyC, _HmacSha512VerifyDart>(
            'cryptolib_hmac_sha512_verify',
          ),
      argon2idHashStr = lib
          .lookupFunction<_Argon2idHashStrC, _Argon2idHashStrDart>(
            'cryptolib_argon2id_hash_str',
          ),
      argon2idVerifyStr = lib
          .lookupFunction<_Argon2idVerifyStrC, _Argon2idVerifyStrDart>(
            'cryptolib_argon2id_verify_str',
          ),
      argon2idDerive = lib
          .lookupFunction<_Argon2idDeriveC, _Argon2idDeriveDart>(
            'cryptolib_argon2id_derive',
          );

  final _Blake2bDart blake2b;
  final _Sha256Dart sha256;
  final _Sha512Dart sha512;
  final _HmacSha512Dart hmacSha512;
  final _HmacSha512VerifyDart hmacSha512Verify;
  final _Argon2idHashStrDart argon2idHashStr;
  final _Argon2idVerifyStrDart argon2idVerifyStr;
  final _Argon2idDeriveDart argon2idDerive;
}
