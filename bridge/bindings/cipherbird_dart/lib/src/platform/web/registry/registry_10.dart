part of '../web_platform.dart';

final Map<String, Function> _registry10 = {
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
};
