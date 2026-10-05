part of '../web_platform.dart';

final Map<String, Function> _registry18 = {
  'cryptolib_noise_read_message':
      (Pointer<NativeType> h, Pointer<NativeType> message, int messageLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_noise_read_message',
            [h.address.toJS, message.address.toJS, messageLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_noise_handshake_finished': (Pointer<NativeType> h) => WebEngine
      .current
      .callInt('_cbw_cryptolib_noise_handshake_finished', [h.address.toJS]),
  'cryptolib_noise_handshake_hash': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_noise_handshake_hash',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_noise_remote_static': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_noise_remote_static',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_noise_split': (Pointer<NativeType> h) =>
      WebEngine.current.callInt('_cbw_cryptolib_noise_split', [h.address.toJS]),
  'cryptolib_noise_encrypt':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> ad,
        int adLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_noise_encrypt',
        [
          h.address.toJS,
          plaintext.address.toJS,
          ptLen.toJS,
          ad.address.toJS,
          adLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_noise_decrypt':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> ad,
        int adLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_noise_decrypt',
        [
          h.address.toJS,
          ciphertext.address.toJS,
          ctLen.toJS,
          ad.address.toJS,
          adLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_noise_decrypt_at':
      (
        Pointer<NativeType> h,
        int nonceCounter,
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> ad,
        int adLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_noise_decrypt_at',
        [
          h.address.toJS,
          (nonceCounter % 4294967296).toJS,
          (nonceCounter ~/ 4294967296).toJS,
          ciphertext.address.toJS,
          ctLen.toJS,
          ad.address.toJS,
          adLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_noise_free': (Pointer<NativeType> h) =>
      WebEngine.current.callVoid('_cbw_cryptolib_noise_free', [h.address.toJS]),
};
