part of '../web_platform.dart';

final Map<String, Function> _registry05 = {
  'cryptolib_cb1_public_sign':
      (
        Pointer<NativeType> out,
        int outCap,
        Pointer<NativeType> outLen,
        Pointer<NativeType> secretKey,
        int skLen,
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> footer,
        int footerLen,
        Pointer<NativeType> implicit,
        int implicitLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_cb1_public_sign', [
        out.address.toJS,
        outCap.toJS,
        outLen.address.toJS,
        secretKey.address.toJS,
        skLen.toJS,
        msg.address.toJS,
        msgLen.toJS,
        footer.address.toJS,
        footerLen.toJS,
        implicit.address.toJS,
        implicitLen.toJS,
      ]),
  'cryptolib_cb1_public_verify':
      (
        Pointer<NativeType> out,
        int outCap,
        Pointer<NativeType> outLen,
        Pointer<NativeType> token,
        int tokenLen,
        Pointer<NativeType> publicKey,
        int pkLen,
        Pointer<NativeType> expectedFooter,
        int expectedFooterLen,
        Pointer<NativeType> implicit,
        int implicitLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_cb1_public_verify', [
        out.address.toJS,
        outCap.toJS,
        outLen.address.toJS,
        token.address.toJS,
        tokenLen.toJS,
        publicKey.address.toJS,
        pkLen.toJS,
        expectedFooter.address.toJS,
        expectedFooterLen.toJS,
        implicit.address.toJS,
        implicitLen.toJS,
      ]),
  'cryptolib_token_formats': (Pointer<NativeType> out, int outCap) => WebEngine
      .current
      .callInt('_cbw_cryptolib_token_formats', [out.address.toJS, outCap.toJS]),
  'cryptolib_token_issue_len':
      (Pointer<NativeType> format, int payloadLen, int footerLen) =>
          WebEngine.current.callInt('_cbw_cryptolib_token_issue_len', [
            format.address.toJS,
            payloadLen.toJS,
            footerLen.toJS,
          ]),
  'cryptolib_token_accept_cap': (Pointer<NativeType> format, int tokenLen) =>
      WebEngine.current.callInt('_cbw_cryptolib_token_accept_cap', [
        format.address.toJS,
        tokenLen.toJS,
      ]),
  'cryptolib_token_keygen':
      (
        Pointer<NativeType> format,
        Pointer<NativeType> secret,
        int secretCap,
        Pointer<NativeType> secretLen,
        Pointer<NativeType> pub,
        int pubCap,
        Pointer<NativeType> pubLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_token_keygen', [
        format.address.toJS,
        secret.address.toJS,
        secretCap.toJS,
        secretLen.address.toJS,
        pub.address.toJS,
        pubCap.toJS,
        pubLen.address.toJS,
      ]),
};
