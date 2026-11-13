part of '../web_platform.dart';

final Map<String, Function> _registry49 = {
  'cryptolib_keyring_slot_type': (Pointer<NativeType> kr, int index) =>
      WebEngine.current.callInt('_cbw_cryptolib_keyring_slot_type', [
        kr.address.toJS,
        index.toJS,
      ]),
  'cryptolib_keyring_hardware_slot':
      (
        Pointer<NativeType> kr,
        int index,
        Pointer<NativeType> outKeyId,
        Pointer<NativeType> outBlob,
      ) => WebEngine.current.callInt('_cbw_cryptolib_keyring_hardware_slot', [
        kr.address.toJS,
        index.toJS,
        outKeyId.address.toJS,
        outBlob.address.toJS,
      ]),
  'cryptolib_keyring_unlock_with_hardware':
      (
        Pointer<NativeType> kr,
        int index,
        Pointer<NativeType> factor,
        int factorLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_keyring_unlock_with_hardware',
        [kr.address.toJS, index.toJS, factor.address.toJS, factorLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_keyring_unlock_with_passphrase':
      (Pointer<NativeType> kr, Pointer<NativeType> passphrase) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_keyring_unlock_with_passphrase',
            [kr.address.toJS, passphrase.address.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_keyring_free': (Pointer<NativeType> kr) => WebEngine.current
      .callVoid('_cbw_cryptolib_keyring_free', [kr.address.toJS]),
  'cryptolib_xwing_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_xwing_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
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
};
