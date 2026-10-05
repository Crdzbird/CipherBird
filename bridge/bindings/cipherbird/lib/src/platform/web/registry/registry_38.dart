part of '../web_platform.dart';

final Map<String, Function> _registry38 = {
  'cryptolib_keccak256': (Pointer<NativeType> msg, int msgLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_keccak256',
        [msg.address.toJS, msgLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_ripemd160': (Pointer<NativeType> msg, int msgLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_ripemd160',
        [msg.address.toJS, msgLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_secp256k1_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_secp256k1_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cryptolib_secp256k1_pubkey':
      (Pointer<NativeType> secretKey, int skLen, int compressed) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_secp256k1_pubkey',
            [secretKey.address.toJS, skLen.toJS, compressed.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_secp256k1_sign':
      (
        Pointer<NativeType> digest32,
        Pointer<NativeType> secretKey,
        int skLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_secp256k1_sign',
        [digest32.address.toJS, secretKey.address.toJS, skLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_secp256k1_verify':
      (
        Pointer<NativeType> digest32,
        Pointer<NativeType> sig,
        int sigLen,
        Pointer<NativeType> publicKey,
        int pkLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_secp256k1_verify', [
        digest32.address.toJS,
        sig.address.toJS,
        sigLen.toJS,
        publicKey.address.toJS,
        pkLen.toJS,
      ]),
  'cryptolib_secp256k1_recover':
      (Pointer<NativeType> digest32, Pointer<NativeType> sig65) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_secp256k1_recover',
            [digest32.address.toJS, sig65.address.toJS],
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
};
