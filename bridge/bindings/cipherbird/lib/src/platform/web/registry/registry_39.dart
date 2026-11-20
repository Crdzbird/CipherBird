part of '../web_platform.dart';

final Map<String, Function> _registry39 = {
  'cipherbird_oprf_derive_keypair':
      (
        Pointer<NativeType> seed,
        int seedLen,
        Pointer<NativeType> info,
        int infoLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_oprf_derive_keypair',
        [seed.address.toJS, seedLen.toJS, info.address.toJS, infoLen.toJS],
        CipherBirdKeyPair.size,
        CipherBirdKeyPair._new,
      ),
  'cipherbird_oprf_blind_free': (Pointer<NativeType> b) => WebEngine.current
      .callVoid('_cbw_cipherbird_oprf_blind_free', [b.address.toJS]),
  'cipherbird_oprf_blind': (Pointer<NativeType> input, int inputLen) =>
      WebEngine.current.callStruct(
        '_cbw_cipherbird_oprf_blind',
        [input.address.toJS, inputLen.toJS],
        CipherBirdOprfBlind.size,
        CipherBirdOprfBlind._new,
      ),
  'cipherbird_oprf_blind_with_scalar':
      (
        Pointer<NativeType> input,
        int inputLen,
        Pointer<NativeType> blind,
        int blindLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_oprf_blind_with_scalar',
        [input.address.toJS, inputLen.toJS, blind.address.toJS, blindLen.toJS],
        CipherBirdOprfBlind.size,
        CipherBirdOprfBlind._new,
      ),
  'cipherbird_oprf_blind_evaluate':
      (
        Pointer<NativeType> sk,
        int skLen,
        Pointer<NativeType> blindedElement,
        int beLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_oprf_blind_evaluate',
        [sk.address.toJS, skLen.toJS, blindedElement.address.toJS, beLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cipherbird_oprf_finalize':
      (
        Pointer<NativeType> input,
        int inputLen,
        Pointer<NativeType> blind,
        int blindLen,
        Pointer<NativeType> evaluatedElement,
        int eeLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_oprf_finalize',
        [
          input.address.toJS,
          inputLen.toJS,
          blind.address.toJS,
          blindLen.toJS,
          evaluatedElement.address.toJS,
          eeLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cipherbird_oprf_evaluate':
      (
        Pointer<NativeType> sk,
        int skLen,
        Pointer<NativeType> input,
        int inputLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_oprf_evaluate',
        [sk.address.toJS, skLen.toJS, input.address.toJS, inputLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cipherbird_opaque_record_free': (Pointer<NativeType> r) => WebEngine.current
      .callVoid('_cbw_cipherbird_opaque_record_free', [r.address.toJS]),
  'cipherbird_opaque_ke1_free': (Pointer<NativeType> k) => WebEngine.current
      .callVoid('_cbw_cipherbird_opaque_ke1_free', [k.address.toJS]),
  'cipherbird_opaque_ke2_free': (Pointer<NativeType> k) => WebEngine.current
      .callVoid('_cbw_cipherbird_opaque_ke2_free', [k.address.toJS]),
  'cipherbird_opaque_ke3_free': (Pointer<NativeType> k) => WebEngine.current
      .callVoid('_cbw_cipherbird_opaque_ke3_free', [k.address.toJS]),
};
