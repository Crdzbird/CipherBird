part of '../web_platform.dart';

final Map<String, Function> _registry19 = {
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
  'cryptolib_hmac_sha256':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> key,
        int keyLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hmac_sha256',
        [msg.address.toJS, msgLen.toJS, key.address.toJS, keyLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hmac_sha256_verify':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> mac,
        int macLen,
        Pointer<NativeType> key,
        int keyLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_hmac_sha256_verify', [
        msg.address.toJS,
        msgLen.toJS,
        mac.address.toJS,
        macLen.toJS,
        key.address.toJS,
        keyLen.toJS,
      ]),
  'cryptolib_hkdf_extract':
      (
        Pointer<NativeType> salt,
        int saltLen,
        Pointer<NativeType> ikm,
        int ikmLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hkdf_extract',
        [salt.address.toJS, saltLen.toJS, ikm.address.toJS, ikmLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
