part of '../web_platform.dart';

final Map<String, Function> _registry21 = {
  'cryptolib_hybrid_kem_encapsulate':
      (
        Pointer<NativeType> publicKey,
        int pkLen,
        Pointer<NativeType> outError,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hybrid_kem_encapsulate',
        [publicKey.address.toJS, pkLen.toJS, outError.address.toJS],
        CipherBirdKemEncapsResult.size,
        CipherBirdKemEncapsResult._new,
      ),
  'cryptolib_hybrid_kem_decapsulate':
      (
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> secretKey,
        int skLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hybrid_kem_decapsulate',
        [
          ciphertext.address.toJS,
          ctLen.toJS,
          secretKey.address.toJS,
          skLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_sntrup_x25519_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_sntrup_x25519_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cryptolib_sntrup_x25519_encapsulate':
      (
        Pointer<NativeType> publicKey,
        int pkLen,
        Pointer<NativeType> outError,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_sntrup_x25519_encapsulate',
        [publicKey.address.toJS, pkLen.toJS, outError.address.toJS],
        CipherBirdKemEncapsResult.size,
        CipherBirdKemEncapsResult._new,
      ),
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
};
