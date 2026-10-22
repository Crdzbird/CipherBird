part of '../web_platform.dart';

final Map<String, Function> _registry51 = {
  'cryptolib_fips_aes_gcm_decrypt':
      (
        Pointer<NativeType> key,
        int keyLen,
        Pointer<NativeType> wire,
        int wireLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_aes_gcm_decrypt',
        [
          key.address.toJS,
          keyLen.toJS,
          wire.address.toJS,
          wireLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fips_p256_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_fips_p256_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cryptolib_fips_p256_ecdh':
      (
        Pointer<NativeType> privateKey,
        int skLen,
        Pointer<NativeType> peerPublic,
        int pkLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_p256_ecdh',
        [
          privateKey.address.toJS,
          skLen.toJS,
          peerPublic.address.toJS,
          pkLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fips_p256_sign':
      (
        Pointer<NativeType> privateKey,
        int skLen,
        Pointer<NativeType> message,
        int msgLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_p256_sign',
        [
          privateKey.address.toJS,
          skLen.toJS,
          message.address.toJS,
          msgLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fips_p256_verify':
      (
        Pointer<NativeType> publicKey,
        int pkLen,
        Pointer<NativeType> message,
        int msgLen,
        Pointer<NativeType> signature,
        int sigLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_fips_p256_verify', [
        publicKey.address.toJS,
        pkLen.toJS,
        message.address.toJS,
        msgLen.toJS,
        signature.address.toJS,
        sigLen.toJS,
      ]),
  'cryptolib_fips_p256_public_key':
      (Pointer<NativeType> privateKey, int skLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_fips_p256_public_key',
            [privateKey.address.toJS, skLen.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
};
