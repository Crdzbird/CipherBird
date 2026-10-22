part of '../web_platform.dart';

final Map<String, Function> _registry22 = {
  'cryptolib_session_accept':
      (
        Pointer<NativeType> handshake,
        int hsLen,
        Pointer<NativeType> prekeyPublic,
        int pkLen,
        Pointer<NativeType> prekeySecret,
        int skLen,
        Pointer<NativeType> outError,
      ) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_session_accept', [
          handshake.address.toJS,
          hsLen.toJS,
          prekeyPublic.address.toJS,
          pkLen.toJS,
          prekeySecret.address.toJS,
          skLen.toJS,
          outError.address.toJS,
        ]),
      ),
  'cryptolib_session_encrypt':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_session_encrypt',
        [
          h.address.toJS,
          pt.address.toJS,
          ptLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
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
};
