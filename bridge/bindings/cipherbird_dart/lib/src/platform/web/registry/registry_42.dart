part of '../web_platform.dart';

final Map<String, Function> _registry42 = {
  'cryptolib_hpke_stego_seal':
      (
        Pointer<NativeType> pkR,
        int pkRLen,
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> info,
        int infoLen,
        Pointer<NativeType> coverPath,
        Pointer<NativeType> outputPath,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hpke_stego_seal',
        [
          pkR.address.toJS,
          pkRLen.toJS,
          plaintext.address.toJS,
          ptLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
          info.address.toJS,
          infoLen.toJS,
          coverPath.address.toJS,
          outputPath.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
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
};
