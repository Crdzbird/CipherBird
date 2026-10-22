part of '../web_platform.dart';

final Map<String, Function> _registry47 = {
  'cryptolib_suite2_seal':
      (
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> recipientKemPublic,
        int rpkLen,
        Pointer<NativeType> signerSigSecret,
        int sskLen,
        Pointer<NativeType> aad,
        int aadLen,
        int suite,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite2_seal',
        [
          plaintext.address.toJS,
          ptLen.toJS,
          recipientKemPublic.address.toJS,
          rpkLen.toJS,
          signerSigSecret.address.toJS,
          sskLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
          suite.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite2_open':
      (
        Pointer<NativeType> envelope,
        int envLen,
        Pointer<NativeType> recipientKemSecret,
        int rskLen,
        Pointer<NativeType> recipientKemPublic,
        int rpkLen,
        Pointer<NativeType> signerSigPublic,
        int spkLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite2_open',
        [
          envelope.address.toJS,
          envLen.toJS,
          recipientKemSecret.address.toJS,
          rskLen.toJS,
          recipientKemPublic.address.toJS,
          rpkLen.toJS,
          signerSigPublic.address.toJS,
          spkLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite2_suite_of': (Pointer<NativeType> envelope, int envLen) =>
      WebEngine.current.callInt('_cbw_cryptolib_suite2_suite_of', [
        envelope.address.toJS,
        envLen.toJS,
      ]),
  'cryptolib_session2_generate_prekey':
      (Pointer<NativeType> responderSigSecret, int sskLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_session2_generate_prekey',
            [responderSigSecret.address.toJS, sskLen.toJS],
            CipherBirdKeyPair.size,
            CipherBirdKeyPair._new,
          ),
  'cryptolib_session2_verify_prekey':
      (
        Pointer<NativeType> bundle,
        int bundleLen,
        Pointer<NativeType> responderSigPublic,
        int rpkLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_session2_verify_prekey',
        [
          bundle.address.toJS,
          bundleLen.toJS,
          responderSigPublic.address.toJS,
          rpkLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
