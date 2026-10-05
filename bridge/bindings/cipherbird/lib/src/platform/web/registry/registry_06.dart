part of '../web_platform.dart';

final Map<String, Function> _registry06 = {
  'cryptolib_suite_open_signed_pq':
      (
        Pointer<NativeType> envelope,
        int envLen,
        Pointer<NativeType> recipientKemSecret,
        int kemSecLen,
        Pointer<NativeType> signerSigPublic,
        int sigPubLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_open_signed_pq',
        [
          envelope.address.toJS,
          envLen.toJS,
          recipientKemSecret.address.toJS,
          kemSecLen.toJS,
          signerSigPublic.address.toJS,
          sigPubLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite_seal_with_file':
      (
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> path,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_seal_with_file',
        [
          pt.address.toJS,
          ptLen.toJS,
          path.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite_open_with_file':
      (
        Pointer<NativeType> envelope,
        int envLen,
        Pointer<NativeType> path,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_open_with_file',
        [
          envelope.address.toJS,
          envLen.toJS,
          path.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite_seal_with_keyring_device':
      (
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> kr,
        Pointer<NativeType> factorKey,
        int factorLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_seal_with_keyring_device',
        [
          pt.address.toJS,
          ptLen.toJS,
          kr.address.toJS,
          factorKey.address.toJS,
          factorLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
