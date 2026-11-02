part of '../web_platform.dart';

final Map<String, Function> _registry03 = {
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
  'cryptolib_paseto_v4_local_encrypt_len': (int msgLen, int footerLen) =>
      WebEngine.current.callInt('_cbw_cryptolib_paseto_v4_local_encrypt_len', [
        msgLen.toJS,
        footerLen.toJS,
      ]),
  'cryptolib_paseto_v4_local_decrypt_cap': (int tokenLen) => WebEngine.current
      .callInt('_cbw_cryptolib_paseto_v4_local_decrypt_cap', [tokenLen.toJS]),
  'cryptolib_paseto_v4_local_encrypt':
      (
        Pointer<NativeType> out,
        int outCap,
        Pointer<NativeType> outLen,
        Pointer<NativeType> key,
        int keyLen,
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> footer,
        int footerLen,
        Pointer<NativeType> implicit,
        int implicitLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_paseto_v4_local_encrypt', [
        out.address.toJS,
        outCap.toJS,
        outLen.address.toJS,
        key.address.toJS,
        keyLen.toJS,
        msg.address.toJS,
        msgLen.toJS,
        footer.address.toJS,
        footerLen.toJS,
        implicit.address.toJS,
        implicitLen.toJS,
      ]),
  'cryptolib_paseto_v4_local_decrypt':
      (
        Pointer<NativeType> out,
        int outCap,
        Pointer<NativeType> outLen,
        Pointer<NativeType> token,
        int tokenLen,
        Pointer<NativeType> key,
        int keyLen,
        Pointer<NativeType> expectedFooter,
        int expectedFooterLen,
        Pointer<NativeType> implicit,
        int implicitLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_paseto_v4_local_decrypt', [
        out.address.toJS,
        outCap.toJS,
        outLen.address.toJS,
        token.address.toJS,
        tokenLen.toJS,
        key.address.toJS,
        keyLen.toJS,
        expectedFooter.address.toJS,
        expectedFooterLen.toJS,
        implicit.address.toJS,
        implicitLen.toJS,
      ]),
};
