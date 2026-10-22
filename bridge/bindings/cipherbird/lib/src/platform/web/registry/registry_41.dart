part of '../web_platform.dart';

final Map<String, Function> _registry41 = {
  'cryptolib_live_entropy_feed':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> data,
        int len,
        int sourceId,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_live_entropy_feed',
        [h.address.toJS, data.address.toJS, len.toJS, sourceId.toJS],
        CipherBirdLiveFeedReport.size,
        CipherBirdLiveFeedReport._new,
      ),
  'cryptolib_live_entropy_generate': (Pointer<NativeType> h, int numBytes) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_live_entropy_generate',
        [h.address.toJS, numBytes.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_live_entropy_status': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_live_entropy_status',
        [h.address.toJS],
        CipherBirdLiveStatus.size,
        CipherBirdLiveStatus._new,
      ),
  'cryptolib_live_entropy_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_live_entropy_free', [h.address.toJS]),
  'cryptolib_image_factor_seal':
      (
        Pointer<NativeType> oprfSecretSeed,
        int seedLen,
        Pointer<NativeType> referenceImagePath,
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> coverPath,
        Pointer<NativeType> outputPath,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_image_factor_seal',
        [
          oprfSecretSeed.address.toJS,
          seedLen.toJS,
          referenceImagePath.address.toJS,
          plaintext.address.toJS,
          ptLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
          coverPath.address.toJS,
          outputPath.address.toJS,
        ],
        CipherBirdResult.size,
        CipherBirdResult._new,
      ),
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
};
