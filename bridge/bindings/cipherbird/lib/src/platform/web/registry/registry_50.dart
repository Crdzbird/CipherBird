part of '../web_platform.dart';

final Map<String, Function> _registry50 = {
  'cryptolib_fips_hkdf':
      (
        int hash,
        Pointer<NativeType> ikm,
        int ikmLen,
        Pointer<NativeType> salt,
        int saltLen,
        Pointer<NativeType> info,
        int infoLen,
        int outLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_hkdf',
        [
          hash.toJS,
          ikm.address.toJS,
          ikmLen.toJS,
          salt.address.toJS,
          saltLen.toJS,
          info.address.toJS,
          infoLen.toJS,
          outLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fips_pbkdf2':
      (
        int hash,
        Pointer<NativeType> password,
        int passwordLen,
        Pointer<NativeType> salt,
        int saltLen,
        int iterations,
        int outLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_pbkdf2',
        [
          hash.toJS,
          password.address.toJS,
          passwordLen.toJS,
          salt.address.toJS,
          saltLen.toJS,
          iterations.toJS,
          outLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fips_random': (int n) => WebEngine.current.callStruct(
    '_cbw_cryptolib_fips_random',
    [n.toJS],
    CipherBirdBufferResult.size,
    CipherBirdBufferResult._new,
  ),
  'cryptolib_fips_aes_gcm_encrypt':
      (
        Pointer<NativeType> key,
        int keyLen,
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_aes_gcm_encrypt',
        [
          key.address.toJS,
          keyLen.toJS,
          pt.address.toJS,
          ptLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
