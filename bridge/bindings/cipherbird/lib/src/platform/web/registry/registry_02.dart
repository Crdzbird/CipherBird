part of '../web_platform.dart';

final Map<String, Function> _registry02 = {
  'cryptolib_argon2id_hash_str':
      (Pointer<NativeType> password, int ops, int mem) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_argon2id_hash_str',
            [
              password.address.toJS,
              (ops % 4294967296).toJS,
              (ops ~/ 4294967296).toJS,
              mem.toJS,
            ],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_argon2id_verify_str':
      (Pointer<NativeType> password, Pointer<NativeType> phcStr) =>
          WebEngine.current.callInt('_cbw_cryptolib_argon2id_verify_str', [
            password.address.toJS,
            phcStr.address.toJS,
          ]),
  'cryptolib_argon2id_derive':
      (
        Pointer<NativeType> password,
        Pointer<NativeType> salt,
        int saltLen,
        int keyLen,
        int ops,
        int mem,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_argon2id_derive',
        [
          password.address.toJS,
          salt.address.toJS,
          saltLen.toJS,
          keyLen.toJS,
          (ops % 4294967296).toJS,
          (ops ~/ 4294967296).toJS,
          mem.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_sym_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_sym_keygen',
    [],
    CipherBirdBufferResult.size,
    CipherBirdBufferResult._new,
  ),
  'cryptolib_xchacha20_encrypt':
      (
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> key,
        int keyLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_xchacha20_encrypt',
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
  'cryptolib_xchacha20_decrypt':
      (
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> key,
        int keyLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_xchacha20_decrypt',
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
};
