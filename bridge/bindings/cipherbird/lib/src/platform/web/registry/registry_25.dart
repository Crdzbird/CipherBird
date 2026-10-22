part of '../web_platform.dart';

final Map<String, Function> _registry25 = {
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
  'cryptolib_frost_sign':
      (
        int identifier,
        Pointer<NativeType> shareSecret,
        int skLen,
        Pointer<NativeType> groupPublicKey,
        int gpkLen,
        Pointer<NativeType> hidingNonce,
        int hnLen,
        Pointer<NativeType> bindingNonce,
        int bnLen,
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> ids,
        Pointer<NativeType> hidingCommits,
        Pointer<NativeType> bindingCommits,
        int count,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_frost_sign',
        [
          identifier.toJS,
          shareSecret.address.toJS,
          skLen.toJS,
          groupPublicKey.address.toJS,
          gpkLen.toJS,
          hidingNonce.address.toJS,
          hnLen.toJS,
          bindingNonce.address.toJS,
          bnLen.toJS,
          msg.address.toJS,
          msgLen.toJS,
          ids.address.toJS,
          hidingCommits.address.toJS,
          bindingCommits.address.toJS,
          count.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
