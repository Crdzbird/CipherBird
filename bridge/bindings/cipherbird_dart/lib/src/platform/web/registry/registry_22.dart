part of '../web_platform.dart';

final Map<String, Function> _registry22 = {
  'cryptolib_session_decrypt':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_session_decrypt',
        [
          h.address.toJS,
          msg.address.toJS,
          msgLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_session_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_session_free', [h.address.toJS]),
  'cryptolib_ml_dsa_keygen': (int level) => WebEngine.current.callStruct(
    '_cbw_cryptolib_ml_dsa_keygen',
    [level.toJS],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cryptolib_ml_dsa_sign':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> secretKey,
        int skLen,
        int level,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_ml_dsa_sign',
        [
          msg.address.toJS,
          msgLen.toJS,
          secretKey.address.toJS,
          skLen.toJS,
          level.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_ml_dsa_verify':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> sig,
        int sigLen,
        Pointer<NativeType> publicKey,
        int pkLen,
        int level,
      ) => WebEngine.current.callInt('_cbw_cryptolib_ml_dsa_verify', [
        msg.address.toJS,
        msgLen.toJS,
        sig.address.toJS,
        sigLen.toJS,
        publicKey.address.toJS,
        pkLen.toJS,
        level.toJS,
      ]),
  'cryptolib_hybrid_sig_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_hybrid_sig_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cryptolib_hybrid_sig_sign':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> secretKey,
        int skLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hybrid_sig_sign',
        [msg.address.toJS, msgLen.toJS, secretKey.address.toJS, skLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
