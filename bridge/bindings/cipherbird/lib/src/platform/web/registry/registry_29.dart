part of '../web_platform.dart';

final Map<String, Function> _registry29 = {
  'cryptolib_bbs_sk_to_pk': (Pointer<NativeType> sk, int skLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_bbs_sk_to_pk',
        [sk.address.toJS, skLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_bbs_sign':
      (
        Pointer<NativeType> sk,
        int skLen,
        Pointer<NativeType> pk,
        int pkLen,
        Pointer<NativeType> header,
        int headerLen,
        Pointer<NativeType> msgs,
        Pointer<NativeType> msgLens,
        int msgCount,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_bbs_sign',
        [
          sk.address.toJS,
          skLen.toJS,
          pk.address.toJS,
          pkLen.toJS,
          header.address.toJS,
          headerLen.toJS,
          msgs.address.toJS,
          msgLens.address.toJS,
          msgCount.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_bbs_verify':
      (
        Pointer<NativeType> pk,
        int pkLen,
        Pointer<NativeType> signature,
        int sigLen,
        Pointer<NativeType> header,
        int headerLen,
        Pointer<NativeType> msgs,
        Pointer<NativeType> msgLens,
        int msgCount,
      ) => WebEngine.current.callInt('_cbw_cryptolib_bbs_verify', [
        pk.address.toJS,
        pkLen.toJS,
        signature.address.toJS,
        sigLen.toJS,
        header.address.toJS,
        headerLen.toJS,
        msgs.address.toJS,
        msgLens.address.toJS,
        msgCount.toJS,
      ]),
};
