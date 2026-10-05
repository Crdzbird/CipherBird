part of '../cipher_bird.dart';

final class _NativeAsymmetric {
  _NativeAsymmetric(DynamicLibrary lib)
    : ed25519Keygen = lib.lookupFunction<_Ed25519KeygenC, _Ed25519KeygenDart>(
        'cryptolib_ed25519_keygen',
      ),
      ed25519KeygenFromSeed = lib
          .lookupFunction<_Ed25519KeygenFromSeedC, _Ed25519KeygenFromSeedDart>(
            'cryptolib_ed25519_keygen_from_seed',
          ),
      ed25519Sign = lib.lookupFunction<_Ed25519SignC, _Ed25519SignDart>(
        'cryptolib_ed25519_sign',
      ),
      ed25519Verify = lib.lookupFunction<_Ed25519VerifyC, _Ed25519VerifyDart>(
        'cryptolib_ed25519_verify',
      ),
      x25519Keygen = lib.lookupFunction<_X25519KeygenC, _X25519KeygenDart>(
        'cryptolib_x25519_keygen',
      ),
      x25519SharedSecret = lib
          .lookupFunction<_X25519SharedSecretC, _X25519SharedSecretDart>(
            'cryptolib_x25519_shared_secret',
          ),
      boxKeygen = lib.lookupFunction<_BoxKeygenC, _BoxKeygenDart>(
        'cryptolib_box_keygen',
      ),
      boxEncrypt = lib.lookupFunction<_BoxEncryptC, _BoxEncryptDart>(
        'cryptolib_box_encrypt',
      ),
      boxDecrypt = lib.lookupFunction<_BoxDecryptC, _BoxDecryptDart>(
        'cryptolib_box_decrypt',
      ),
      sealedboxEncrypt = lib
          .lookupFunction<_SealedBoxEncryptC, _SealedBoxEncryptDart>(
            'cryptolib_sealedbox_encrypt',
          ),
      sealedboxDecrypt = lib
          .lookupFunction<_SealedBoxDecryptC, _SealedBoxDecryptDart>(
            'cryptolib_sealedbox_decrypt',
          );

  final _Ed25519KeygenDart ed25519Keygen;
  final _Ed25519KeygenFromSeedDart ed25519KeygenFromSeed;
  final _Ed25519SignDart ed25519Sign;
  final _Ed25519VerifyDart ed25519Verify;
  final _X25519KeygenDart x25519Keygen;
  final _X25519SharedSecretDart x25519SharedSecret;
  final _BoxKeygenDart boxKeygen;
  final _BoxEncryptDart boxEncrypt;
  final _BoxDecryptDart boxDecrypt;
  final _SealedBoxEncryptDart sealedboxEncrypt;
  final _SealedBoxDecryptDart sealedboxDecrypt;
}
