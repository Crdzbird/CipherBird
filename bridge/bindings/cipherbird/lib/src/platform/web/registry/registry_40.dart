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
  'cryptolib_entropy_assess_file_health_v2':
      (Pointer<NativeType> path, int maxBytes, double floorBitsPerByte) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_entropy_assess_file_health_v2',
            [path.address.toJS, maxBytes.toJS, floorBitsPerByte.toJS],
            CipherBirdHealthReport2.size,
            CipherBirdHealthReport2._new,
          ),
  'cryptolib_live_entropy_new':
      (
        double minBitsPerByte,
        int requireRct,
        double minCreditedBits,
        Pointer<NativeType> outError,
      ) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_live_entropy_new', [
          minBitsPerByte.toJS,
          requireRct.toJS,
          minCreditedBits.toJS,
          outError.address.toJS,
        ]),
      ),
};
