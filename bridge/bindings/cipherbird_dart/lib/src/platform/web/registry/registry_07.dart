part of '../web_platform.dart';

final Map<String, Function> _registry07 = {
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
  'cryptolib_suite_seal_with_keyring_passphrase':
      (
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> kr,
        Pointer<NativeType> passphrase,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_seal_with_keyring_passphrase',
        [
          pt.address.toJS,
          ptLen.toJS,
          kr.address.toJS,
          passphrase.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite_open_with_keyring_passphrase':
      (
        Pointer<NativeType> envelope,
        int envLen,
        Pointer<NativeType> kr,
        Pointer<NativeType> passphrase,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_open_with_keyring_passphrase',
        [
          envelope.address.toJS,
          envLen.toJS,
          kr.address.toJS,
          passphrase.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_suite_seal_threshold':
      (
        Pointer<NativeType> pt,
        int ptLen,
        int n,
        int k,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> outShares,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_suite_seal_threshold',
        [
          pt.address.toJS,
          ptLen.toJS,
          n.toJS,
          k.toJS,
          aad.address.toJS,
          aadLen.toJS,
          outShares.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
