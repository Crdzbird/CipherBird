part of '../web_platform.dart';

final Map<String, Function> _registry05 = {
  'cryptolib_suite_open_pq':
      (
        Pointer<NativeType> envelope,
        int envLen,
        Pointer<NativeType> recipientKemSecret,
        int kemSecLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_open_pq',
        [
          envelope.address.toJS,
          envLen.toJS,
          recipientKemSecret.address.toJS,
          kemSecLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite_seal_signed_pq':
      (
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> recipientKemPublic,
        int kemPubLen,
        Pointer<NativeType> signerSigSecret,
        int sigSecLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_seal_signed_pq',
        [
          pt.address.toJS,
          ptLen.toJS,
          recipientKemPublic.address.toJS,
          kemPubLen.toJS,
          signerSigSecret.address.toJS,
          sigSecLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite_seal_signed_pq_sntrup':
      (
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> recipientKemPublic,
        int kemPubLen,
        Pointer<NativeType> signerSigSecret,
        int sigSecLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_seal_signed_pq_sntrup',
        [
          pt.address.toJS,
          ptLen.toJS,
          recipientKemPublic.address.toJS,
          kemPubLen.toJS,
          signerSigSecret.address.toJS,
          sigSecLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
