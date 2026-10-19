part of '../web_platform.dart';

final Map<String, Function> _registry44 = {
  'cryptolib_keyring_unlock_with_hardware':
      (
        Pointer<NativeType> kr,
        int index,
        Pointer<NativeType> factor,
        int factorLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_keyring_unlock_with_hardware',
        [kr.address.toJS, index.toJS, factor.address.toJS, factorLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_keyring_unlock_with_passphrase':
      (Pointer<NativeType> kr, Pointer<NativeType> passphrase) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_keyring_unlock_with_passphrase',
            [kr.address.toJS, passphrase.address.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_keyring_free': (Pointer<NativeType> kr) => WebEngine.current
      .callVoid('_cbw_cryptolib_keyring_free', [kr.address.toJS]),
  'cryptolib_version': () =>
      Pointer<Utf8>._(WebEngine.current.callInt('_cbw_cryptolib_version', [])),
};
