part of '../web_platform.dart';

final Map<String, Function> _registry18 = {
  'cryptolib_vault_free': (Pointer<NativeType> vault) => WebEngine.current
      .callVoid('_cbw_cryptolib_vault_free', [vault.address.toJS]),
  'cryptolib_asym_bundle_generate': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_asym_bundle_generate',
    [],
    CipherBirdAsymBundle.size,
    CipherBirdAsymBundle._new,
  ),
  'cryptolib_asym_vault_seal':
      (
        Pointer<NativeType> sender,
        Pointer<NativeType> recipientBoxPub,
        int rpubLen,
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> aad,
        Pointer<NativeType> outError,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_asym_vault_seal',
        [
          sender.address.toJS,
          recipientBoxPub.address.toJS,
          rpubLen.toJS,
          plaintext.address.toJS,
          ptLen.toJS,
          aad.address.toJS,
          outError.address.toJS,
        ],
        CipherBirdPacket.size,
        CipherBirdPacket._new,
      ),
  'cryptolib_asym_vault_open':
      (
        Pointer<NativeType> packet,
        Pointer<NativeType> recipient,
        Pointer<NativeType> senderSignPub,
        int spubLen,
        Pointer<NativeType> aad,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_asym_vault_open',
        [
          packet.address.toJS,
          recipient.address.toJS,
          senderSignPub.address.toJS,
          spubLen.toJS,
          aad.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_entropy_from_file':
      (Pointer<NativeType> path, Pointer<NativeType> outError) =>
          Pointer<Void>._(
            WebEngine.current.callInt('_cbw_cryptolib_entropy_from_file', [
              path.address.toJS,
              outError.address.toJS,
            ]),
          ),
  'cryptolib_entropy_from_file_deterministic':
      (Pointer<NativeType> path, Pointer<NativeType> outError) =>
          Pointer<Void>._(
            WebEngine.current.callInt(
              '_cbw_cryptolib_entropy_from_file_deterministic',
              [path.address.toJS, outError.address.toJS],
            ),
          ),
  'cryptolib_entropy_from_file_with_policy':
      (
        Pointer<NativeType> path,
        int deterministic,
        double minBitsPerByte,
        int requireRct,
        Pointer<NativeType> outError,
      ) => Pointer<Void>._(
        WebEngine.current.callInt(
          '_cbw_cryptolib_entropy_from_file_with_policy',
          [
            path.address.toJS,
            deterministic.toJS,
            minBitsPerByte.toJS,
            requireRct.toJS,
            outError.address.toJS,
          ],
        ),
      ),
};
