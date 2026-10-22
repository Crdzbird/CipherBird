part of '../web_platform.dart';

final Map<String, Function> _registry23 = {
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
  'cryptolib_hybrid_sig_verify':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> sig,
        int sigLen,
        Pointer<NativeType> publicKey,
        int pkLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_hybrid_sig_verify', [
        msg.address.toJS,
        msgLen.toJS,
        sig.address.toJS,
        sigLen.toJS,
        publicKey.address.toJS,
        pkLen.toJS,
      ]),
  'cryptolib_slh_dsa_keygen': (int level, int hashFamily) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_slh_dsa_keygen',
        [level.toJS, hashFamily.toJS],
        CipherBirdKeyPair.size,
        CipherBirdKeyPair._new,
      ),
  'cryptolib_slh_dsa_sign':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> secretKey,
        int skLen,
        int level,
        int hashFamily,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_slh_dsa_sign',
        [
          msg.address.toJS,
          msgLen.toJS,
          secretKey.address.toJS,
          skLen.toJS,
          level.toJS,
          hashFamily.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
