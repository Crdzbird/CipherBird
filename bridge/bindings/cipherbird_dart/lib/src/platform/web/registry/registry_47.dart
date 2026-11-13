part of '../web_platform.dart';

final Map<String, Function> _registry47 = {
  'cryptolib_hpke_stego_open':
      (
        Pointer<NativeType> skR,
        int skRLen,
        Pointer<NativeType> enc,
        int encLen,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> info,
        int infoLen,
        Pointer<NativeType> stegoPath,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hpke_stego_open',
        [
          skR.address.toJS,
          skRLen.toJS,
          enc.address.toJS,
          encLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
          info.address.toJS,
          infoLen.toJS,
          stegoPath.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_drbg_instantiate':
      (
        Pointer<NativeType> entropy,
        int entropyLen,
        Pointer<NativeType> nonce,
        int nonceLen,
        Pointer<NativeType> personalization,
        int persoLen,
        Pointer<NativeType> outError,
      ) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_drbg_instantiate', [
          entropy.address.toJS,
          entropyLen.toJS,
          nonce.address.toJS,
          nonceLen.toJS,
          personalization.address.toJS,
          persoLen.toJS,
          outError.address.toJS,
        ]),
      ),
  'cryptolib_drbg_generate':
      (
        Pointer<NativeType> h,
        int numBytes,
        Pointer<NativeType> additional,
        int additionalLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_drbg_generate',
        [
          h.address.toJS,
          numBytes.toJS,
          additional.address.toJS,
          additionalLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_drbg_reseed':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> entropy,
        int entropyLen,
        Pointer<NativeType> additional,
        int additionalLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_drbg_reseed',
        [
          h.address.toJS,
          entropy.address.toJS,
          entropyLen.toJS,
          additional.address.toJS,
          additionalLen.toJS,
        ],
        CipherBirdResult.size,
        CipherBirdResult._new,
      ),
  'cryptolib_drbg_free': (Pointer<NativeType> h) =>
      WebEngine.current.callVoid('_cbw_cryptolib_drbg_free', [h.address.toJS]),
  'cryptolib_fortuna_new': () => Pointer<Void>._(
    WebEngine.current.callInt('_cbw_cryptolib_fortuna_new', []),
  ),
};
