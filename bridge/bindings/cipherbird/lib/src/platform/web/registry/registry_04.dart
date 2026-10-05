part of '../web_platform.dart';

final Map<String, Function> _registry04 = {
  'cryptolib_molecular_seal_with_key':
      (
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> masterKey,
        int keyLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_molecular_seal_with_key',
        [
          plaintext.address.toJS,
          ptLen.toJS,
          masterKey.address.toJS,
          keyLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_molecular_open_with_key':
      (
        Pointer<NativeType> envelope,
        int envLen,
        Pointer<NativeType> masterKey,
        int keyLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_molecular_open_with_key',
        [
          envelope.address.toJS,
          envLen.toJS,
          masterKey.address.toJS,
          keyLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite_seal_pq':
      (
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> recipientKemPublic,
        int kemPubLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_seal_pq',
        [
          pt.address.toJS,
          ptLen.toJS,
          recipientKemPublic.address.toJS,
          kemPubLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite_seal_pq_sntrup':
      (
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> recipientKemPublic,
        int kemPubLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_seal_pq_sntrup',
        [
          pt.address.toJS,
          ptLen.toJS,
          recipientKemPublic.address.toJS,
          kemPubLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
