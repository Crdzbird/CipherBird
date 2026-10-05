part of '../web_platform.dart';

final Map<String, Function> _registry20 = {
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
  'cryptolib_hybrid_kem_encapsulate':
      (
        Pointer<NativeType> publicKey,
        int pkLen,
        Pointer<NativeType> outError,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hybrid_kem_encapsulate',
        [publicKey.address.toJS, pkLen.toJS, outError.address.toJS],
        CipherBirdKemEncapsResult.size,
        CipherBirdKemEncapsResult._new,
      ),
  'cryptolib_hybrid_kem_decapsulate':
      (
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> secretKey,
        int skLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hybrid_kem_decapsulate',
        [
          ciphertext.address.toJS,
          ctLen.toJS,
          secretKey.address.toJS,
          skLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_sntrup_x25519_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_sntrup_x25519_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cryptolib_sntrup_x25519_encapsulate':
      (
        Pointer<NativeType> publicKey,
        int pkLen,
        Pointer<NativeType> outError,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_sntrup_x25519_encapsulate',
        [publicKey.address.toJS, pkLen.toJS, outError.address.toJS],
        CipherBirdKemEncapsResult.size,
        CipherBirdKemEncapsResult._new,
      ),
};
