part of '../web_platform.dart';

final Map<String, Function> _registry14 = {
  'cryptolib_vault_from_entropy':
      (Pointer<NativeType> entropy, int kdfPreset) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_vault_from_entropy', [
          entropy.address.toJS,
          kdfPreset.toJS,
        ]),
      ),
  'cryptolib_vault_seal':
      (
        Pointer<NativeType> vault,
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> aad,
        Pointer<NativeType> outError,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_vault_seal',
        [
          vault.address.toJS,
          plaintext.address.toJS,
          ptLen.toJS,
          aad.address.toJS,
          outError.address.toJS,
        ],
        CipherBirdPacket.size,
        CipherBirdPacket._new,
      ),
  'cryptolib_vault_seal_boosted':
      (
        Pointer<NativeType> vault,
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> aad,
        Pointer<NativeType> boost,
        Pointer<NativeType> outError,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_vault_seal_boosted',
        [
          vault.address.toJS,
          plaintext.address.toJS,
          ptLen.toJS,
          aad.address.toJS,
          boost.address.toJS,
          outError.address.toJS,
        ],
        CipherBirdPacket.size,
        CipherBirdPacket._new,
      ),
  'cryptolib_vault_open':
      (
        Pointer<NativeType> vault,
        Pointer<NativeType> packet,
        Pointer<NativeType> aad,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_vault_open',
        [vault.address.toJS, packet.address.toJS, aad.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_vault_open_boosted':
      (
        Pointer<NativeType> vault,
        Pointer<NativeType> packet,
        Pointer<NativeType> aad,
        Pointer<NativeType> boost,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_vault_open_boosted',
        [
          vault.address.toJS,
          packet.address.toJS,
          aad.address.toJS,
          boost.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_vault_public_key': (Pointer<NativeType> vault) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_vault_public_key',
        [vault.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_packet_serialise': (Pointer<NativeType> packet) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_packet_serialise',
        [packet.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
