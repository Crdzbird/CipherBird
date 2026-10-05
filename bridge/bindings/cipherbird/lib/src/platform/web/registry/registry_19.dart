part of '../web_platform.dart';

final Map<String, Function> _registry19 = {
  'cryptolib_hmac_sha256':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> key,
        int keyLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hmac_sha256',
        [msg.address.toJS, msgLen.toJS, key.address.toJS, keyLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hmac_sha256_verify':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> mac,
        int macLen,
        Pointer<NativeType> key,
        int keyLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_hmac_sha256_verify', [
        msg.address.toJS,
        msgLen.toJS,
        mac.address.toJS,
        macLen.toJS,
        key.address.toJS,
        keyLen.toJS,
      ]),
  'cryptolib_hkdf_extract':
      (
        Pointer<NativeType> salt,
        int saltLen,
        Pointer<NativeType> ikm,
        int ikmLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hkdf_extract',
        [salt.address.toJS, saltLen.toJS, ikm.address.toJS, ikmLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hkdf_expand':
      (
        Pointer<NativeType> prk,
        int prkLen,
        Pointer<NativeType> info,
        int infoLen,
        int outLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hkdf_expand',
        [
          prk.address.toJS,
          prkLen.toJS,
          info.address.toJS,
          infoLen.toJS,
          outLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hkdf_derive':
      (
        Pointer<NativeType> ikm,
        int ikmLen,
        Pointer<NativeType> salt,
        int saltLen,
        Pointer<NativeType> info,
        int infoLen,
        int outLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hkdf_derive',
        [
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
  'cryptolib_kem_encaps_free': (Pointer<NativeType> r) => WebEngine.current
      .callVoid('_cbw_cryptolib_kem_encaps_free', [r.address.toJS]),
  'cryptolib_ml_kem_keygen': (int level) => WebEngine.current.callStruct(
    '_cbw_cryptolib_ml_kem_keygen',
    [level.toJS],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
};
