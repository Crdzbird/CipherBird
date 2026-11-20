part of '../web_platform.dart';

final Map<String, Function> _registry19 = {
  'cipherbird_packet_deserialise':
      (Pointer<NativeType> data, int len, Pointer<NativeType> outError) =>
          WebEngine.current.callStruct(
            '_cbw_cipherbird_packet_deserialise',
            [data.address.toJS, len.toJS, outError.address.toJS],
            CipherBirdPacket.size,
            CipherBirdPacket._new,
          ),
  'cipherbird_vault_free': (Pointer<NativeType> vault) => WebEngine.current
      .callVoid('_cbw_cipherbird_vault_free', [vault.address.toJS]),
  'cipherbird_asym_bundle_generate': () => WebEngine.current.callStruct(
    '_cbw_cipherbird_asym_bundle_generate',
    [],
    CipherBirdAsymBundle.size,
    CipherBirdAsymBundle._new,
  ),
  'cipherbird_asym_vault_seal':
      (
        Pointer<NativeType> sender,
        Pointer<NativeType> recipientBoxPub,
        int rpubLen,
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> aad,
        Pointer<NativeType> outError,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_asym_vault_seal',
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
  'cipherbird_asym_vault_open':
      (
        Pointer<NativeType> packet,
        Pointer<NativeType> recipient,
        Pointer<NativeType> senderSignPub,
        int spubLen,
        Pointer<NativeType> aad,
      ) => WebEngine.current.callStruct(
        '_cbw_cipherbird_asym_vault_open',
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
  'cipherbird_entropy_from_file':
      (Pointer<NativeType> path, Pointer<NativeType> outError) =>
          Pointer<Void>._(
            WebEngine.current.callInt('_cbw_cipherbird_entropy_from_file', [
              path.address.toJS,
              outError.address.toJS,
            ]),
          ),
  'cipherbird_entropy_from_file_deterministic':
      (Pointer<NativeType> path, Pointer<NativeType> outError) =>
          Pointer<Void>._(
            WebEngine.current.callInt(
              '_cbw_cipherbird_entropy_from_file_deterministic',
              [path.address.toJS, outError.address.toJS],
            ),
          ),
};
