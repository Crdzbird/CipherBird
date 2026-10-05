part of '../web_platform.dart';

final Map<String, Function> _registry12 = {
  'cryptolib_stream_dec_pull':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> outTag,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_stream_dec_pull',
        [
          h.address.toJS,
          ciphertext.address.toJS,
          ctLen.toJS,
          outTag.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_stream_dec_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_stream_dec_free', [h.address.toJS]),
  'cryptolib_ed25519_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_ed25519_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cryptolib_ed25519_keygen_from_seed':
      (Pointer<NativeType> seed, int seedLen) => WebEngine.current.callStruct(
        '_cbw_cryptolib_ed25519_keygen_from_seed',
        [seed.address.toJS, seedLen.toJS],
        CipherBirdKeyPair.size,
        CipherBirdKeyPair._new,
      ),
  'cryptolib_ed25519_sign':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> secretKey,
        int skLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_ed25519_sign',
        [msg.address.toJS, msgLen.toJS, secretKey.address.toJS, skLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_ed25519_verify':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> sig,
        int sigLen,
        Pointer<NativeType> publicKey,
        int pkLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_ed25519_verify', [
        msg.address.toJS,
        msgLen.toJS,
        sig.address.toJS,
        sigLen.toJS,
        publicKey.address.toJS,
        pkLen.toJS,
      ]),
  'cryptolib_x25519_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_x25519_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cryptolib_x25519_shared_secret':
      (
        Pointer<NativeType> ourSecret,
        int ourLen,
        Pointer<NativeType> theirPublic,
        int theirLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_x25519_shared_secret',
        [
          ourSecret.address.toJS,
          ourLen.toJS,
          theirPublic.address.toJS,
          theirLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_box_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_box_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
};
