part of '../web_platform.dart';

final Map<String, Function> _registry09 = {
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
  'cryptolib_suite_open_with_keyring_device':
      (
        Pointer<NativeType> envelope,
        int envLen,
        Pointer<NativeType> kr,
        Pointer<NativeType> factorKey,
        int factorLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_open_with_keyring_device',
        [
          envelope.address.toJS,
          envLen.toJS,
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
