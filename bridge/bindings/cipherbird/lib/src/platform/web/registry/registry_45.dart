part of '../web_platform.dart';

final Map<String, Function> _registry45 = {
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
};
