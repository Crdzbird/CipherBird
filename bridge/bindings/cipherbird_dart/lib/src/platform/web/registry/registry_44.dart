part of '../web_platform.dart';

final Map<String, Function> _registry44 = {
  'cryptolib_keyring_serialise': (Pointer<NativeType> kr) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_keyring_serialise',
        [kr.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_keyring_deserialise':
      (Pointer<NativeType> blob, int len, Pointer<NativeType> outError) =>
          Pointer<Void>._(
            WebEngine.current.callInt('_cbw_cryptolib_keyring_deserialise', [
              blob.address.toJS,
              len.toJS,
              outError.address.toJS,
            ]),
          ),
  'cryptolib_keyring_unlock_with_device':
      (Pointer<NativeType> kr, Pointer<NativeType> factorKey, int len) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_keyring_unlock_with_device',
            [kr.address.toJS, factorKey.address.toJS, len.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_keyring_add_hardware_slot':
      (Pointer<NativeType> kr, Pointer<NativeType> keyId, int keyIdLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_keyring_add_hardware_slot',
            [kr.address.toJS, keyId.address.toJS, keyIdLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_keyring_set_hardware_blob':
      (
        Pointer<NativeType> kr,
        int index,
        Pointer<NativeType> blob,
        int blobLen,
      ) => WebEngine.current.callInt(
        '_cbw_cryptolib_keyring_set_hardware_blob',
        [kr.address.toJS, index.toJS, blob.address.toJS, blobLen.toJS],
      ),
  'cryptolib_keyring_slot_type': (Pointer<NativeType> kr, int index) =>
      WebEngine.current.callInt('_cbw_cryptolib_keyring_slot_type', [
        kr.address.toJS,
        index.toJS,
      ]),
  'cryptolib_keyring_hardware_slot':
      (
        Pointer<NativeType> kr,
        int index,
        Pointer<NativeType> outKeyId,
        Pointer<NativeType> outBlob,
      ) => WebEngine.current.callInt('_cbw_cryptolib_keyring_hardware_slot', [
        kr.address.toJS,
        index.toJS,
        outKeyId.address.toJS,
        outBlob.address.toJS,
      ]),
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
  'cryptolib_xwing_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_xwing_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
};
