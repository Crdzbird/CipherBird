part of '../web_platform.dart';

final Map<String, Function> _registry41 = {
  'cryptolib_image_factor_open':
      (
        Pointer<NativeType> oprfSecretSeed,
        int seedLen,
        Pointer<NativeType> referenceImagePath,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> stegoPath,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_image_factor_open',
        [
          oprfSecretSeed.address.toJS,
          seedLen.toJS,
          referenceImagePath.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
          stegoPath.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
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
};
