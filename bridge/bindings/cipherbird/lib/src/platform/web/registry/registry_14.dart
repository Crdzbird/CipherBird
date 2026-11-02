part of '../web_platform.dart';

final Map<String, Function> _registry14 = {
  'cryptolib_aes256gcm_decrypt':
      (
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> key,
        int keyLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_aes256gcm_decrypt',
        [
          ciphertext.address.toJS,
          ctLen.toJS,
          key.address.toJS,
          keyLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_aes256gcm_available': () =>
      WebEngine.current.callInt('_cbw_cryptolib_aes256gcm_available', []),
  'cryptolib_stream_enc_create': (Pointer<NativeType> key) => Pointer<Void>._(
    WebEngine.current.callInt('_cbw_cryptolib_stream_enc_create', [
      key.address.toJS,
    ]),
  ),
  'cryptolib_stream_enc_header': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_stream_enc_header',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_stream_enc_push':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> plaintext,
        int ptLen,
        int tag,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_stream_enc_push',
        [h.address.toJS, plaintext.address.toJS, ptLen.toJS, tag.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_stream_enc_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_stream_enc_free', [h.address.toJS]),
  'cryptolib_stream_dec_create':
      (Pointer<NativeType> key, Pointer<NativeType> header) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_stream_dec_create', [
          key.address.toJS,
          header.address.toJS,
        ]),
      ),
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
};
