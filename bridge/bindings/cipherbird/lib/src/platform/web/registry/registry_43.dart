part of '../web_platform.dart';

final Map<String, Function> _registry43 = {
  'cryptolib_drbg_generate':
      (
        Pointer<NativeType> h,
        int numBytes,
        Pointer<NativeType> additional,
        int additionalLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_drbg_generate',
        [
          h.address.toJS,
          numBytes.toJS,
          additional.address.toJS,
          additionalLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_drbg_reseed':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> entropy,
        int entropyLen,
        Pointer<NativeType> additional,
        int additionalLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_drbg_reseed',
        [
          h.address.toJS,
          entropy.address.toJS,
          entropyLen.toJS,
          additional.address.toJS,
          additionalLen.toJS,
        ],
        CipherBirdResult.size,
        CipherBirdResult._new,
      ),
  'cryptolib_drbg_free': (Pointer<NativeType> h) =>
      WebEngine.current.callVoid('_cbw_cryptolib_drbg_free', [h.address.toJS]),
  'cryptolib_fortuna_new': () => Pointer<Void>._(
    WebEngine.current.callInt('_cbw_cryptolib_fortuna_new', []),
  ),
  'cryptolib_fortuna_add_entropy':
      (
        Pointer<NativeType> h,
        int sourceId,
        Pointer<NativeType> data,
        int len,
      ) => WebEngine.current.callVoid('_cbw_cryptolib_fortuna_add_entropy', [
        h.address.toJS,
        sourceId.toJS,
        data.address.toJS,
        len.toJS,
      ]),
  'cryptolib_fortuna_generate': (Pointer<NativeType> h, int numBytes) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_fortuna_generate',
        [h.address.toJS, numBytes.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fortuna_reseed': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_fortuna_reseed', [h.address.toJS]),
  'cryptolib_fortuna_reseed_count': (Pointer<NativeType> h) => WebEngine.current
      .callU64('_cbw_cryptolib_fortuna_reseed_count', [h.address.toJS]),
  'cryptolib_fortuna_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_fortuna_free', [h.address.toJS]),
  'cryptolib_keyring_create': () => Pointer<Void>._(
    WebEngine.current.callInt('_cbw_cryptolib_keyring_create', []),
  ),
  'cryptolib_keyring_add_device_slot':
      (Pointer<NativeType> kr, Pointer<NativeType> factorKey, int len) =>
          WebEngine.current.callInt('_cbw_cryptolib_keyring_add_device_slot', [
            kr.address.toJS,
            factorKey.address.toJS,
            len.toJS,
          ]),
  'cryptolib_keyring_add_passphrase_slot':
      (Pointer<NativeType> kr, Pointer<NativeType> passphrase, int kdfPreset) =>
          WebEngine.current.callInt(
            '_cbw_cryptolib_keyring_add_passphrase_slot',
            [kr.address.toJS, passphrase.address.toJS, kdfPreset.toJS],
          ),
  'cryptolib_keyring_slot_count': (Pointer<NativeType> kr) => WebEngine.current
      .callInt('_cbw_cryptolib_keyring_slot_count', [kr.address.toJS]),
  'cryptolib_keyring_remove_slot': (Pointer<NativeType> kr, int index) =>
      WebEngine.current.callInt('_cbw_cryptolib_keyring_remove_slot', [
        kr.address.toJS,
        index.toJS,
      ]),
};
