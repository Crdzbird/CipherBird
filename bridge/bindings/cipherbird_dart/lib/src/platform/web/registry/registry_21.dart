part of '../web_platform.dart';

final Map<String, Function> _registry21 = {
  'cryptolib_sntrup_x25519_decapsulate':
      (
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> secretKey,
        int skLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_sntrup_x25519_decapsulate',
        [
          ciphertext.address.toJS,
          ctLen.toJS,
          secretKey.address.toJS,
          skLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_session_generate_prekey': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_session_generate_prekey',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cryptolib_session_initiate':
      (
        Pointer<NativeType> responderPrekeyPublic,
        int pkLen,
        Pointer<NativeType> outError,
      ) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_session_initiate', [
          responderPrekeyPublic.address.toJS,
          pkLen.toJS,
          outError.address.toJS,
        ]),
      ),
  'cryptolib_session_handshake': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_session_handshake',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
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
};
