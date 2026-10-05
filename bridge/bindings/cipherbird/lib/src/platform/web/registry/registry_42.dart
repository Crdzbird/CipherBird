part of '../web_platform.dart';

final Map<String, Function> _registry42 = {
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
  'cryptolib_fortuna_add_entropy':
      (
        Pointer<NativeType> h,
        int sourceId,
        Pointer<NativeType> data,
        int len,
      ) => WebEngine.current.callVoid('_cbw_cryptolib_fortuna_add_entropy', [
        h.address.toJS,
        sourceId.toJS,
        data.address.toJS,
        len.toJS,
      ]),
  'cryptolib_fortuna_generate': (Pointer<NativeType> h, int numBytes) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_fortuna_generate',
        [h.address.toJS, numBytes.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fortuna_reseed': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_fortuna_reseed', [h.address.toJS]),
  'cryptolib_fortuna_reseed_count': (Pointer<NativeType> h) => WebEngine.current
      .callU64('_cbw_cryptolib_fortuna_reseed_count', [h.address.toJS]),
  'cryptolib_fortuna_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_fortuna_free', [h.address.toJS]),
  'cryptolib_keyring_create': () => Pointer<Void>._(
    WebEngine.current.callInt('_cbw_cryptolib_keyring_create', []),
  ),
};
