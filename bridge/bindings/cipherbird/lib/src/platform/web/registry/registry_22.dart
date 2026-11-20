part of '../web_platform.dart';

final Map<String, Function> _registry22 = {
  'cipherbird_noise_create':
      (
        int initiator,
        Pointer<NativeType> staticPublic,
        int staticPublicLen,
        Pointer<NativeType> staticSecret,
        int staticSecretLen,
        Pointer<NativeType> prologue,
        int prologueLen,
      ) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cipherbird_noise_create', [
          initiator.toJS,
          staticPublic.address.toJS,
          staticPublicLen.toJS,
          staticSecret.address.toJS,
          staticSecretLen.toJS,
          prologue.address.toJS,
          prologueLen.toJS,
        ]),
      ),
  'cipherbird_noise_write_message':
      (Pointer<NativeType> h, Pointer<NativeType> payload, int payloadLen) =>
          WebEngine.current.callStruct(
            '_cbw_cipherbird_noise_write_message',
            [h.address.toJS, payload.address.toJS, payloadLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cipherbird_noise_read_message':
      (Pointer<NativeType> h, Pointer<NativeType> message, int messageLen) =>
          WebEngine.current.callStruct(
            '_cbw_cipherbird_noise_read_message',
            [h.address.toJS, message.address.toJS, messageLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cipherbird_noise_handshake_finished': (Pointer<NativeType> h) => WebEngine
      .current
      .callInt('_cbw_cipherbird_noise_handshake_finished', [h.address.toJS]),
  'cipherbird_noise_handshake_hash': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cipherbird_noise_handshake_hash',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cipherbird_noise_remote_static': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cipherbird_noise_remote_static',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cipherbird_noise_split': (Pointer<NativeType> h) => WebEngine.current
      .callInt('_cbw_cipherbird_noise_split', [h.address.toJS]),
  'cipherbird_noise_encrypt':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> ad,
        int adLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_noise_encrypt',
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
};
