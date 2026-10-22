part of '../web_platform.dart';

final Map<String, Function> _registry31 = {
  'cryptolib_bbs_commit_with_nym':
      (
        Pointer<NativeType> committedMsgs,
        Pointer<NativeType> committedLens,
        int committedCount,
        Pointer<NativeType> proverNyms,
        Pointer<NativeType> nymLens,
        int nymCount,
        Pointer<NativeType> secretProverBlind,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_bbs_commit_with_nym',
        [
          committedMsgs.address.toJS,
          committedLens.address.toJS,
          committedCount.toJS,
          proverNyms.address.toJS,
          nymLens.address.toJS,
          nymCount.toJS,
          secretProverBlind.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_bbs_blind_sign_with_nym':
      (
        Pointer<NativeType> sk,
        int skLen,
        Pointer<NativeType> pk,
        int pkLen,
        Pointer<NativeType> commitmentWithProof,
        int commitLen,
        Pointer<NativeType> header,
        int headerLen,
        Pointer<NativeType> msgs,
        Pointer<NativeType> msgLens,
        int msgCount,
        Pointer<NativeType> signerNymEntropy,
        int entropyLen,
        int lengthNymVector,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_bbs_blind_sign_with_nym',
        [
          sk.address.toJS,
          skLen.toJS,
          pk.address.toJS,
          pkLen.toJS,
          commitmentWithProof.address.toJS,
          commitLen.toJS,
          header.address.toJS,
          headerLen.toJS,
          msgs.address.toJS,
          msgLens.address.toJS,
          msgCount.toJS,
          signerNymEntropy.address.toJS,
          entropyLen.toJS,
          (lengthNymVector % 4294967296).toJS,
          (lengthNymVector ~/ 4294967296).toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_bbs_finalize_nym_secrets':
      (
        Pointer<NativeType> proverNyms,
        Pointer<NativeType> nymLens,
        int nymCount,
        Pointer<NativeType> signerNymEntropy,
        int entropyLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_bbs_finalize_nym_secrets',
        [
          proverNyms.address.toJS,
          nymLens.address.toJS,
          nymCount.toJS,
          signerNymEntropy.address.toJS,
          entropyLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
