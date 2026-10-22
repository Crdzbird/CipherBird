part of '../web_platform.dart';

final Map<String, Function> _registry45 = {
  'cryptolib_xwing_keypair_from_seed':
      (Pointer<NativeType> seed, int seedLen) => WebEngine.current.callStruct(
        '_cbw_cryptolib_xwing_keypair_from_seed',
        [seed.address.toJS, seedLen.toJS],
        CipherBirdKeyPair.size,
        CipherBirdKeyPair._new,
      ),
  'cryptolib_xwing_encapsulate':
      (
        Pointer<NativeType> publicKey,
        int pkLen,
        Pointer<NativeType> outError,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_xwing_encapsulate',
        [publicKey.address.toJS, pkLen.toJS, outError.address.toJS],
        CipherBirdKemEncapsResult.size,
        CipherBirdKemEncapsResult._new,
      ),
  'cryptolib_xwing_decapsulate':
      (
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> secretKey,
        int skLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_xwing_decapsulate',
        [
          ciphertext.address.toJS,
          ctLen.toJS,
          secretKey.address.toJS,
          skLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hpke_kem_available': (int kem) => WebEngine.current.callInt(
    '_cbw_cryptolib_hpke_kem_available',
    [kem.toJS],
  ),
  'cryptolib_hpke_keygen_kem': (int kem) => WebEngine.current.callStruct(
    '_cbw_cryptolib_hpke_keygen_kem',
    [kem.toJS],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cryptolib_hpke_derive_keypair_kem':
      (int kem, Pointer<NativeType> ikm, int ikmLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_hpke_derive_keypair_kem',
            [kem.toJS, ikm.address.toJS, ikmLen.toJS],
            CipherBirdKeyPair.size,
            CipherBirdKeyPair._new,
          ),
};
