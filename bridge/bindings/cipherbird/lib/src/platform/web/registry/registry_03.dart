part of '../web_platform.dart';

final Map<String, Function> _registry03 = {
  'cryptolib_committing_encrypt':
      (
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> key,
        int keyLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_committing_encrypt',
        [
          plaintext.address.toJS,
          ptLen.toJS,
          key.address.toJS,
          keyLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_committing_decrypt':
      (
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> key,
        int keyLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_committing_decrypt',
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
  'cryptolib_molecular_seal':
      (
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> passphrase,
        Pointer<NativeType> aad,
        int aadLen,
        int ops,
        int mem,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_molecular_seal',
        [
          plaintext.address.toJS,
          ptLen.toJS,
          passphrase.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
          (ops % 4294967296).toJS,
          (ops ~/ 4294967296).toJS,
          mem.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_molecular_open':
      (
        Pointer<NativeType> envelope,
        int envLen,
        Pointer<NativeType> passphrase,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_molecular_open',
        [
          envelope.address.toJS,
          envLen.toJS,
          passphrase.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
