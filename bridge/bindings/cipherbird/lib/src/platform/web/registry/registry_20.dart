part of '../web_platform.dart';

final Map<String, Function> _registry20 = {
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
  'cryptolib_ml_kem_encapsulate':
      (
        Pointer<NativeType> publicKey,
        int pkLen,
        int level,
        Pointer<NativeType> outError,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_ml_kem_encapsulate',
        [publicKey.address.toJS, pkLen.toJS, level.toJS, outError.address.toJS],
        CipherBirdKemEncapsResult.size,
        CipherBirdKemEncapsResult._new,
      ),
  'cryptolib_ml_kem_decapsulate':
      (
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> secretKey,
        int skLen,
        int level,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_ml_kem_decapsulate',
        [
          ciphertext.address.toJS,
          ctLen.toJS,
          secretKey.address.toJS,
          skLen.toJS,
          level.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hybrid_kem_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_hybrid_kem_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
};
