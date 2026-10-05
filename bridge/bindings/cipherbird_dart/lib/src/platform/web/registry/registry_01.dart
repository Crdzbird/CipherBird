part of '../web_platform.dart';

final Map<String, Function> _registry01 = {
  'cryptolib_buffer_free': (Pointer<NativeType> buf) => WebEngine.current
      .callVoid('_cbw_cryptolib_buffer_free', [buf.address.toJS]),
  'cryptolib_str_free': (Pointer<NativeType> str) =>
      WebEngine.current.callVoid('_cbw_cryptolib_str_free', [str.address.toJS]),
  'cryptolib_keypair_free': (Pointer<NativeType> kp) => WebEngine.current
      .callVoid('_cbw_cryptolib_keypair_free', [kp.address.toJS]),
  'cryptolib_bundle_free': (Pointer<NativeType> b) => WebEngine.current
      .callVoid('_cbw_cryptolib_bundle_free', [b.address.toJS]),
  'cryptolib_packet_free': (Pointer<NativeType> p) => WebEngine.current
      .callVoid('_cbw_cryptolib_packet_free', [p.address.toJS]),
  'cryptolib_derived_keys_free': (Pointer<NativeType> dk) => WebEngine.current
      .callVoid('_cbw_cryptolib_derived_keys_free', [dk.address.toJS]),
  'cryptolib_entropy_info_free': (Pointer<NativeType> info) => WebEngine.current
      .callVoid('_cbw_cryptolib_entropy_info_free', [info.address.toJS]),
  'cryptolib_init': () => WebEngine.current.callInt('_cbw_cryptolib_init', []),
  'cryptolib_random_bytes': (int n) => WebEngine.current.callStruct(
    '_cbw_cryptolib_random_bytes',
    [n.toJS],
    CipherBirdBufferResult.size,
    CipherBirdBufferResult._new,
  ),
  'cryptolib_secure_equal':
      (Pointer<NativeType> a, int aLen, Pointer<NativeType> b, int bLen) =>
          WebEngine.current.callInt('_cbw_cryptolib_secure_equal', [
            a.address.toJS,
            aLen.toJS,
            b.address.toJS,
            bLen.toJS,
          ]),
  'cryptolib_blake2b':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> key,
        int keyLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_blake2b',
        [msg.address.toJS, msgLen.toJS, key.address.toJS, keyLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_sha256': (Pointer<NativeType> msg, int msgLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_sha256',
        [msg.address.toJS, msgLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_sha512': (Pointer<NativeType> msg, int msgLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_sha512',
        [msg.address.toJS, msgLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hmac_sha512':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> key,
        int keyLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hmac_sha512',
        [msg.address.toJS, msgLen.toJS, key.address.toJS, keyLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hmac_sha512_verify':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> mac,
        int macLen,
        Pointer<NativeType> key,
        int keyLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_hmac_sha512_verify', [
        msg.address.toJS,
        msgLen.toJS,
        mac.address.toJS,
        macLen.toJS,
        key.address.toJS,
        keyLen.toJS,
      ]),
};
