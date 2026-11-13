part of '../web_platform.dart';

final Map<String, Function> _registry44 = {
  'cryptolib_stego_embed_encrypted':
      (
        Pointer<NativeType> coverPath,
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> outputPath,
        Pointer<NativeType> masterKey,
        int keyLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_stego_embed_encrypted',
        [
          coverPath.address.toJS,
          plaintext.address.toJS,
          ptLen.toJS,
          outputPath.address.toJS,
          masterKey.address.toJS,
          keyLen.toJS,
        ],
        CipherBirdResult.size,
        CipherBirdResult._new,
      ),
  'cryptolib_stego_extract_decrypt':
      (
        Pointer<NativeType> stegoPath,
        Pointer<NativeType> masterKey,
        int keyLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_stego_extract_decrypt',
        [stegoPath.address.toJS, masterKey.address.toJS, keyLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_physical_seal':
      (
        Pointer<NativeType> keyMediaPath,
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> coverPath,
        Pointer<NativeType> outputPath,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_physical_seal',
        [
          keyMediaPath.address.toJS,
          plaintext.address.toJS,
          ptLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
          coverPath.address.toJS,
          outputPath.address.toJS,
        ],
        CipherBirdResult.size,
        CipherBirdResult._new,
      ),
  'cryptolib_physical_open':
      (
        Pointer<NativeType> keyMediaPath,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> stegoPath,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_physical_open',
        [
          keyMediaPath.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
          stegoPath.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fec_encode': (Pointer<NativeType> data, int len, int scheme) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_fec_encode',
        [data.address.toJS, len.toJS, scheme.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fec_decode':
      (Pointer<NativeType> data, int len, int scheme, int originalLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_fec_decode',
            [data.address.toJS, len.toJS, scheme.toJS, originalLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
};
