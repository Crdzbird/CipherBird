part of '../web_platform.dart';

final Map<String, Function> _registry40 = {
  'cryptolib_physical_open':
      (
        Pointer<NativeType> keyMediaPath,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> stegoPath,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_physical_open',
        [
          keyMediaPath.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
          stegoPath.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fec_encode': (Pointer<NativeType> data, int len, int scheme) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_fec_encode',
        [data.address.toJS, len.toJS, scheme.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fec_decode':
      (Pointer<NativeType> data, int len, int scheme, int originalLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_fec_decode',
            [data.address.toJS, len.toJS, scheme.toJS, originalLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_stego_inspect': (Pointer<NativeType> path) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_stego_inspect',
        [path.address.toJS],
        CipherBirdFileInspection.size,
        CipherBirdFileInspection._new,
      ),
  'cryptolib_stego_content_digest': (Pointer<NativeType> path) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_stego_content_digest',
        [path.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_stego_detect_hidden': (Pointer<NativeType> path) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_stego_detect_hidden',
        [path.address.toJS],
        CipherBirdHiddenDataReport.size,
        CipherBirdHiddenDataReport._new,
      ),
  'cryptolib_entropy_assess_file_health':
      (Pointer<NativeType> path, int maxBytes) => WebEngine.current.callStruct(
        '_cbw_cryptolib_entropy_assess_file_health',
        [path.address.toJS, maxBytes.toJS],
        CipherBirdHealthReport.size,
        CipherBirdHealthReport._new,
      ),
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
};
