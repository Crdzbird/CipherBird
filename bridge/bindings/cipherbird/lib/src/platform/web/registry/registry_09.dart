part of '../web_platform.dart';

final Map<String, Function> _registry09 = {
  'cryptolib_sealed_open':
      (
        int tier,
        Pointer<NativeType> envelope,
        int envLen,
        Pointer<NativeType> recipientSecret,
        int rsecLen,
        Pointer<NativeType> recipientPublic,
        int rpubLen,
        Pointer<NativeType> senderPublic,
        int spubLen,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> purpose,
        int purposeLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_sealed_open',
        [
          tier.toJS,
          envelope.address.toJS,
          envLen.toJS,
          recipientSecret.address.toJS,
          rsecLen.toJS,
          recipientPublic.address.toJS,
          rpubLen.toJS,
          senderPublic.address.toJS,
          spubLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
          purpose.address.toJS,
          purposeLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_sealed_inspect': (Pointer<NativeType> envelope, int envLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_sealed_inspect',
        [envelope.address.toJS, envLen.toJS],
        CipherBirdSealedInfo.size,
        CipherBirdSealedInfo._new,
      ),
  'cryptolib_sealed_addressed_to':
      (
        Pointer<NativeType> envelope,
        int envLen,
        Pointer<NativeType> recipientPublic,
        int rpubLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_sealed_addressed_to', [
        envelope.address.toJS,
        envLen.toJS,
        recipientPublic.address.toJS,
        rpubLen.toJS,
      ]),
  'cryptolib_sealed_sealer_begin':
      (
        int tier,
        Pointer<NativeType> recipientPublic,
        int rpubLen,
        Pointer<NativeType> senderSecret,
        int ssecLen,
        Pointer<NativeType> purpose,
        int purposeLen,
        Pointer<NativeType> outError,
      ) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_sealed_sealer_begin', [
          tier.toJS,
          recipientPublic.address.toJS,
          rpubLen.toJS,
          senderSecret.address.toJS,
          ssecLen.toJS,
          purpose.address.toJS,
          purposeLen.toJS,
          outError.address.toJS,
        ]),
      ),
  'cryptolib_sealed_sealer_preamble': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_sealed_sealer_preamble',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
