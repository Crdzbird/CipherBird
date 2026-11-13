part of '../web_platform.dart';

final Map<String, Function> _registry43 = {
  'cryptolib_p256_verify':
      (
        Pointer<NativeType> publicKey,
        int pkLen,
        Pointer<NativeType> message,
        int msgLen,
        Pointer<NativeType> signature,
        int sigLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_p256_verify', [
        publicKey.address.toJS,
        pkLen.toJS,
        message.address.toJS,
        msgLen.toJS,
        signature.address.toJS,
        sigLen.toJS,
      ]),
  'cryptolib_p256_import_pkcs8_der': (Pointer<NativeType> der, int derLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_p256_import_pkcs8_der',
        [der.address.toJS, derLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_p256_import_pkcs8_pem': (Pointer<NativeType> pem, int pemLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_p256_import_pkcs8_pem',
        [pem.address.toJS, pemLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_stego_embed':
      (
        Pointer<NativeType> coverPath,
        Pointer<NativeType> payload,
        int payloadLen,
        Pointer<NativeType> outputPath,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_stego_embed',
        [
          coverPath.address.toJS,
          payload.address.toJS,
          payloadLen.toJS,
          outputPath.address.toJS,
        ],
        CipherBirdResult.size,
        CipherBirdResult._new,
      ),
  'cryptolib_stego_extract': (Pointer<NativeType> stegoPath) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_stego_extract',
        [stegoPath.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_stego_capacity': (Pointer<NativeType> coverPath) => WebEngine
      .current
      .callInt('_cbw_cryptolib_stego_capacity', [coverPath.address.toJS]),
  'cryptolib_stego_embed_keyed':
      (
        Pointer<NativeType> coverPath,
        Pointer<NativeType> payload,
        int payloadLen,
        Pointer<NativeType> outputPath,
        Pointer<NativeType> key,
        int keyLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_stego_embed_keyed',
        [
          coverPath.address.toJS,
          payload.address.toJS,
          payloadLen.toJS,
          outputPath.address.toJS,
          key.address.toJS,
          keyLen.toJS,
        ],
        CipherBirdResult.size,
        CipherBirdResult._new,
      ),
  'cryptolib_stego_extract_keyed':
      (Pointer<NativeType> stegoPath, Pointer<NativeType> key, int keyLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_stego_extract_keyed',
            [stegoPath.address.toJS, key.address.toJS, keyLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
};
