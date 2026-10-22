part of '../web_platform.dart';

final Map<String, Function> _registry28 = {
  'cryptolib_hpke_seal':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> pt,
        int ptLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hpke_seal',
        [
          h.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
          pt.address.toJS,
          ptLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hpke_open':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> ct,
        int ctLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hpke_open',
        [
          h.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
          ct.address.toJS,
          ctLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hpke_export':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> exporterContext,
        int ctxLen,
        int length,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hpke_export',
        [
          h.address.toJS,
          exporterContext.address.toJS,
          ctxLen.toJS,
          length.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hpke_context_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_hpke_context_free', [h.address.toJS]),
  'cryptolib_ecvrf_keygen': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_ecvrf_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cryptolib_ecvrf_public_key': (Pointer<NativeType> sk, int skLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_ecvrf_public_key',
        [sk.address.toJS, skLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_ecvrf_prove':
      (
        Pointer<NativeType> sk,
        int skLen,
        Pointer<NativeType> alpha,
        int alphaLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_ecvrf_prove',
        [sk.address.toJS, skLen.toJS, alpha.address.toJS, alphaLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_ecvrf_proof_to_hash': (Pointer<NativeType> pi, int piLen) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_ecvrf_proof_to_hash',
        [pi.address.toJS, piLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
