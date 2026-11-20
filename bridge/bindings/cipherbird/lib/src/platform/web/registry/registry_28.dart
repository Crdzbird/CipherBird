part of '../web_platform.dart';

final Map<String, Function> _registry28 = {
  'cipherbird_slh_dsa_verify':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> sig,
        int sigLen,
        Pointer<NativeType> publicKey,
        int pkLen,
        int level,
        int hashFamily,
      ) => WebEngine.current.callInt('_cbw_cipherbird_slh_dsa_verify', [
        msg.address.toJS,
        msgLen.toJS,
        sig.address.toJS,
        sigLen.toJS,
        publicKey.address.toJS,
        pkLen.toJS,
        level.toJS,
        hashFamily.toJS,
      ]),
  'cipherbird_bls_keygen': () => WebEngine.current.callStruct(
    '_cbw_cipherbird_bls_keygen',
    [],
    CipherBirdKeyPair.size,
    CipherBirdKeyPair._new,
  ),
  'cipherbird_bls_keygen_from_ikm': (Pointer<NativeType> ikm, int ikmLen) =>
      WebEngine.current.callStruct(
        '_cbw_cipherbird_bls_keygen_from_ikm',
        [ikm.address.toJS, ikmLen.toJS],
        CipherBirdKeyPair.size,
        CipherBirdKeyPair._new,
      ),
  'cipherbird_bls_sign':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> secretKey,
        int skLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_bls_sign',
        [msg.address.toJS, msgLen.toJS, secretKey.address.toJS, skLen.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cipherbird_bls_verify':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> sig,
        int sigLen,
        Pointer<NativeType> publicKey,
        int pkLen,
      ) => WebEngine.current.callInt('_cbw_cipherbird_bls_verify', [
        msg.address.toJS,
        msgLen.toJS,
        sig.address.toJS,
        sigLen.toJS,
        publicKey.address.toJS,
        pkLen.toJS,
      ]),
  'cipherbird_bls_aggregate':
      (Pointer<NativeType> sigs, Pointer<NativeType> sigLens, int count) =>
          WebEngine.current.callStruct(
            '_cbw_cipherbird_bls_aggregate',
            [sigs.address.toJS, sigLens.address.toJS, count.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cipherbird_bls_aggregate_verify':
      (
        Pointer<NativeType> msgs,
        Pointer<NativeType> msgLens,
        Pointer<NativeType> pks,
        Pointer<NativeType> pkLens,
        int count,
        Pointer<NativeType> aggSig,
        int aggSigLen,
      ) => WebEngine.current.callInt('_cbw_cipherbird_bls_aggregate_verify', [
        msgs.address.toJS,
        msgLens.address.toJS,
        pks.address.toJS,
        pkLens.address.toJS,
        count.toJS,
        aggSig.address.toJS,
        aggSigLen.toJS,
      ]),
  'cipherbird_frost_keygen_free': (Pointer<NativeType> kg) => WebEngine.current
      .callVoid('_cbw_cipherbird_frost_keygen_free', [kg.address.toJS]),
};
