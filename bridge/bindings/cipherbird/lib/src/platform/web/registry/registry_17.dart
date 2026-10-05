part of '../web_platform.dart';

final Map<String, Function> _registry17 = {
  'cryptolib_blake3': (Pointer<NativeType> msg, int msgLen, int outLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_blake3',
        [msg.address.toJS, msgLen.toJS, outLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_blake3_keyed':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> key,
        int keyLen,
        int outLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_blake3_keyed',
        [
          msg.address.toJS,
          msgLen.toJS,
          key.address.toJS,
          keyLen.toJS,
          outLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_blake3_derive_key':
      (
        Pointer<NativeType> context,
        Pointer<NativeType> ikm,
        int ikmLen,
        int outLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_blake3_derive_key',
        [context.address.toJS, ikm.address.toJS, ikmLen.toJS, outLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_blake3_hasher_create': (Pointer<NativeType> key, int keyLen) =>
      Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_blake3_hasher_create', [
          key.address.toJS,
          keyLen.toJS,
        ]),
      ),
  'cryptolib_blake3_hasher_update':
      (Pointer<NativeType> h, Pointer<NativeType> data, int len) =>
          WebEngine.current.callInt('_cbw_cryptolib_blake3_hasher_update', [
            h.address.toJS,
            data.address.toJS,
            len.toJS,
          ]),
  'cryptolib_blake3_hasher_finalize': (Pointer<NativeType> h, int outLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_blake3_hasher_finalize',
        [h.address.toJS, outLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_blake3_hasher_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_blake3_hasher_free', [h.address.toJS]),
  'cryptolib_noise_create':
      (
        int initiator,
        Pointer<NativeType> staticPublic,
        int staticPublicLen,
        Pointer<NativeType> staticSecret,
        int staticSecretLen,
        Pointer<NativeType> prologue,
        int prologueLen,
      ) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_noise_create', [
          initiator.toJS,
          staticPublic.address.toJS,
          staticPublicLen.toJS,
          staticSecret.address.toJS,
          staticSecretLen.toJS,
          prologue.address.toJS,
          prologueLen.toJS,
        ]),
      ),
  'cryptolib_noise_write_message':
      (Pointer<NativeType> h, Pointer<NativeType> payload, int payloadLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_noise_write_message',
            [h.address.toJS, payload.address.toJS, payloadLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
};
