part of '../web_platform.dart';

final Map<String, Function> _registry47 = {
  'cryptolib_session2_initiate':
      (
        Pointer<NativeType> bundle,
        int bundleLen,
        Pointer<NativeType> responderSigPublic,
        int rpkLen,
        Pointer<NativeType> initiatorSigPublic,
        int ipkLen,
        Pointer<NativeType> initiatorSigSecret,
        int iskLen,
        Pointer<NativeType> outError,
      ) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_session2_initiate', [
          bundle.address.toJS,
          bundleLen.toJS,
          responderSigPublic.address.toJS,
          rpkLen.toJS,
          initiatorSigPublic.address.toJS,
          ipkLen.toJS,
          initiatorSigSecret.address.toJS,
          iskLen.toJS,
          outError.address.toJS,
        ]),
      ),
  'cryptolib_session2_handshake': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_session2_handshake',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_session2_claimed_initiator':
      (Pointer<NativeType> handshake, int hsLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_session2_claimed_initiator',
            [handshake.address.toJS, hsLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_session2_accept':
      (
        Pointer<NativeType> handshake,
        int hsLen,
        Pointer<NativeType> bundle,
        int bundleLen,
        Pointer<NativeType> prekeySecret,
        int pskLen,
        Pointer<NativeType> responderSigPublic,
        int rpkLen,
        Pointer<NativeType> responderSigSecret,
        int rskLen,
        Pointer<NativeType> expectedInitiatorSigPublic,
        int ipkLen,
        Pointer<NativeType> outError,
      ) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_session2_accept', [
          handshake.address.toJS,
          hsLen.toJS,
          bundle.address.toJS,
          bundleLen.toJS,
          prekeySecret.address.toJS,
          pskLen.toJS,
          responderSigPublic.address.toJS,
          rpkLen.toJS,
          responderSigSecret.address.toJS,
          rskLen.toJS,
          expectedInitiatorSigPublic.address.toJS,
          ipkLen.toJS,
          outError.address.toJS,
        ]),
      ),
  'cryptolib_session2_encrypt':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_session2_encrypt',
        [
          h.address.toJS,
          pt.address.toJS,
          ptLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
