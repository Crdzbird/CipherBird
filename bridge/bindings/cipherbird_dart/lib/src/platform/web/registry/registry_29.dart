part of '../web_platform.dart';

final Map<String, Function> _registry29 = {
  'cryptolib_ecvrf_verify':
      (
        Pointer<NativeType> pk,
        int pkLen,
        Pointer<NativeType> alpha,
        int alphaLen,
        Pointer<NativeType> pi,
        int piLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_ecvrf_verify',
        [
          pk.address.toJS,
          pkLen.toJS,
          alpha.address.toJS,
          alphaLen.toJS,
          pi.address.toJS,
          piLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_bbs_keygen':
      (
        Pointer<NativeType> keyMaterial,
        int kmLen,
        Pointer<NativeType> keyInfo,
        int kiLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_bbs_keygen',
        [
          keyMaterial.address.toJS,
          kmLen.toJS,
          keyInfo.address.toJS,
          kiLen.toJS,
        ],
        CipherBirdKeyPair.size,
        CipherBirdKeyPair._new,
      ),
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
};
