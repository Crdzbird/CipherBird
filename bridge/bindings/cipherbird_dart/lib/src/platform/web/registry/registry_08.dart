part of '../web_platform.dart';

final Map<String, Function> _registry08 = {
  'cryptolib_suite_open_threshold':
      (
        Pointer<NativeType> envelope,
        int envLen,
        Pointer<NativeType> shares,
        int sharesLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_open_threshold',
        [
          envelope.address.toJS,
          envLen.toJS,
          shares.address.toJS,
          sharesLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite_evm_address': (Pointer<NativeType> publicKey, int pkLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_evm_address',
        [publicKey.address.toJS, pkLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_sealed_generate_recipient': (int tier) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_sealed_generate_recipient',
        [tier.toJS],
        CipherBirdKeyPair.size,
        CipherBirdKeyPair._new,
      ),
  'cryptolib_sealed_generate_sender': (int tier) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_sealed_generate_sender',
        [tier.toJS],
        CipherBirdKeyPair.size,
        CipherBirdKeyPair._new,
      ),
  'cryptolib_sealed_seal':
      (
        int tier,
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> recipientPublic,
        int rpubLen,
        Pointer<NativeType> senderSecret,
        int ssecLen,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> purpose,
        int purposeLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_sealed_seal',
        [
          tier.toJS,
          pt.address.toJS,
          ptLen.toJS,
          recipientPublic.address.toJS,
          rpubLen.toJS,
          senderSecret.address.toJS,
          ssecLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
          purpose.address.toJS,
          purposeLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
