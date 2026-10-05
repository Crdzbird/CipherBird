part of '../web_platform.dart';

final Map<String, Function> _registry10 = {
  'cryptolib_sealed_sealer_push':
      (Pointer<NativeType> h, Pointer<NativeType> chunk, int chunkLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_sealed_sealer_push',
            [h.address.toJS, chunk.address.toJS, chunkLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_sealed_sealer_finalize':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> lastChunk,
        int lastLen,
        Pointer<NativeType> outTrailer,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_sealed_sealer_finalize',
        [
          h.address.toJS,
          lastChunk.address.toJS,
          lastLen.toJS,
          outTrailer.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_sealed_sealer_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_sealed_sealer_free', [h.address.toJS]),
  'cryptolib_sealed_opener_begin':
      (
        int tier,
        Pointer<NativeType> preamble,
        int preLen,
        Pointer<NativeType> recipientSecret,
        int rsecLen,
        Pointer<NativeType> recipientPublic,
        int rpubLen,
        Pointer<NativeType> senderPublic,
        int spubLen,
        Pointer<NativeType> purpose,
        int purposeLen,
        Pointer<NativeType> outError,
      ) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_sealed_opener_begin', [
          tier.toJS,
          preamble.address.toJS,
          preLen.toJS,
          recipientSecret.address.toJS,
          rsecLen.toJS,
          recipientPublic.address.toJS,
          rpubLen.toJS,
          senderPublic.address.toJS,
          spubLen.toJS,
          purpose.address.toJS,
          purposeLen.toJS,
          outError.address.toJS,
        ]),
      ),
  'cryptolib_sealed_opener_pull':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> ct,
        int ctLen,
        Pointer<NativeType> outFinal,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_sealed_opener_pull',
        [h.address.toJS, ct.address.toJS, ctLen.toJS, outFinal.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_sealed_opener_finalize':
      (Pointer<NativeType> h, Pointer<NativeType> trailer, int trailerLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_sealed_opener_finalize',
            [h.address.toJS, trailer.address.toJS, trailerLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_sealed_opener_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_sealed_opener_free', [h.address.toJS]),
};
