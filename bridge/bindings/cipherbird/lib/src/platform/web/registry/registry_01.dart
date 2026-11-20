part of '../web_platform.dart';

final Map<String, Function> _registry01 = {
  'cipherbird_buffer_free': (Pointer<NativeType> buf) => WebEngine.current
      .callVoid('_cbw_cipherbird_buffer_free', [buf.address.toJS]),
  'cipherbird_str_free': (Pointer<NativeType> str) => WebEngine.current
      .callVoid('_cbw_cipherbird_str_free', [str.address.toJS]),
  'cipherbird_keypair_free': (Pointer<NativeType> kp) => WebEngine.current
      .callVoid('_cbw_cipherbird_keypair_free', [kp.address.toJS]),
  'cipherbird_bundle_free': (Pointer<NativeType> b) => WebEngine.current
      .callVoid('_cbw_cipherbird_bundle_free', [b.address.toJS]),
  'cipherbird_packet_free': (Pointer<NativeType> p) => WebEngine.current
      .callVoid('_cbw_cipherbird_packet_free', [p.address.toJS]),
  'cipherbird_derived_keys_free': (Pointer<NativeType> dk) => WebEngine.current
      .callVoid('_cbw_cipherbird_derived_keys_free', [dk.address.toJS]),
  'cipherbird_entropy_info_free': (Pointer<NativeType> info) => WebEngine
      .current
      .callVoid('_cbw_cipherbird_entropy_info_free', [info.address.toJS]),
  'cipherbird_init': () =>
      WebEngine.current.callInt('_cbw_cipherbird_init', []),
  'cipherbird_random_bytes': (int n) => WebEngine.current.callStruct(
    '_cbw_cipherbird_random_bytes',
    [n.toJS],
    CipherBirdBufferResult.size,
    CipherBirdBufferResult._new,
  ),
  'cipherbird_secure_equal':
      (Pointer<NativeType> a, int aLen, Pointer<NativeType> b, int bLen) =>
          WebEngine.current.callInt('_cbw_cipherbird_secure_equal', [
            a.address.toJS,
            aLen.toJS,
            b.address.toJS,
            bLen.toJS,
          ]),
  'cipherbird_blake2b':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> key,
        int keyLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_blake2b',
        [msg.address.toJS, msgLen.toJS, key.address.toJS, keyLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cipherbird_blake2b_keyed':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> key,
        int keyLen,
        int outLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_blake2b_keyed',
        [
          msg.address.toJS,
          msgLen.toJS,
          key.address.toJS,
          keyLen.toJS,
          outLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cipherbird_sha256': (Pointer<NativeType> msg, int msgLen) =>
      WebEngine.current.callStruct(
        '_cbw_cipherbird_sha256',
        [msg.address.toJS, msgLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cipherbird_sha512': (Pointer<NativeType> msg, int msgLen) =>
      WebEngine.current.callStruct(
        '_cbw_cipherbird_sha512',
        [msg.address.toJS, msgLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cipherbird_hmac_sha512':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> key,
        int keyLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_hmac_sha512',
        [msg.address.toJS, msgLen.toJS, key.address.toJS, keyLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
