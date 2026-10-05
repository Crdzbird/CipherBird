part of '../web_platform.dart';

final Map<String, Function> _registry24 = {
  'cryptolib_bls_verify':
      (
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> sig,
        int sigLen,
        Pointer<NativeType> publicKey,
        int pkLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_bls_verify', [
        msg.address.toJS,
        msgLen.toJS,
        sig.address.toJS,
        sigLen.toJS,
        publicKey.address.toJS,
        pkLen.toJS,
      ]),
  'cryptolib_bls_aggregate':
      (Pointer<NativeType> sigs, Pointer<NativeType> sigLens, int count) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_bls_aggregate',
            [sigs.address.toJS, sigLens.address.toJS, count.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_bls_aggregate_verify':
      (
        Pointer<NativeType> msgs,
        Pointer<NativeType> msgLens,
        Pointer<NativeType> pks,
        Pointer<NativeType> pkLens,
        int count,
        Pointer<NativeType> aggSig,
        int aggSigLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_bls_aggregate_verify', [
        msgs.address.toJS,
        msgLens.address.toJS,
        pks.address.toJS,
        pkLens.address.toJS,
        count.toJS,
        aggSig.address.toJS,
        aggSigLen.toJS,
      ]),
  'cryptolib_frost_keygen_free': (Pointer<NativeType> kg) => WebEngine.current
      .callVoid('_cbw_cryptolib_frost_keygen_free', [kg.address.toJS]),
  'cryptolib_frost_commit_free': (Pointer<NativeType> c) => WebEngine.current
      .callVoid('_cbw_cryptolib_frost_commit_free', [c.address.toJS]),
  'cryptolib_frost_keygen': (int n, int t) => WebEngine.current.callStruct(
    '_cbw_cryptolib_frost_keygen',
    [n.toJS, t.toJS],
    CipherBirdFrostKeyGen.size,
    CipherBirdFrostKeyGen._new,
  ),
  'cryptolib_frost_commit':
      (Pointer<NativeType> shareSecret, int skLen, int identifier) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_frost_commit',
            [shareSecret.address.toJS, skLen.toJS, identifier.toJS],
            CipherBirdFrostCommit.size,
            CipherBirdFrostCommit._new,
          ),
  'cryptolib_frost_commit_with_nonces':
      (
        int identifier,
        Pointer<NativeType> hidingNonce,
        int hnLen,
        Pointer<NativeType> bindingNonce,
        int bnLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_frost_commit_with_nonces',
        [
          identifier.toJS,
          hidingNonce.address.toJS,
          hnLen.toJS,
          bindingNonce.address.toJS,
          bnLen.toJS,
        ],
        CipherBirdFrostCommit.size,
        CipherBirdFrostCommit._new,
      ),
};
