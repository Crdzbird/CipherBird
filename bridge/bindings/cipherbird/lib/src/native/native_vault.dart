part of '../cipher_bird.dart';

final class _NativeVault {
  _NativeVault(DynamicLibrary lib)
    : vaultCreate = lib.lookupFunction<_VaultCreateC, _VaultCreateDart>(
        'cipherbird_vault_create',
      ),
      vaultFromEntropy = lib
          .lookupFunction<_VaultFromEntropyC, _VaultFromEntropyDart>(
            'cipherbird_vault_from_entropy',
          ),
      vaultSeal = lib.lookupFunction<_VaultSealC, _VaultSealDart>(
        'cipherbird_vault_seal',
      ),
      vaultSealBoosted = lib
          .lookupFunction<_VaultSealBoostedC, _VaultSealBoostedDart>(
            'cipherbird_vault_seal_boosted',
          ),
      vaultOpen = lib.lookupFunction<_VaultOpenC, _VaultOpenDart>(
        'cipherbird_vault_open',
      ),
      vaultOpenBoosted = lib
          .lookupFunction<_VaultOpenBoostedC, _VaultOpenBoostedDart>(
            'cipherbird_vault_open_boosted',
          ),
      vaultPublicKey = lib
          .lookupFunction<_VaultPublicKeyC, _VaultPublicKeyDart>(
            'cipherbird_vault_public_key',
          ),
      packetSerialise = lib
          .lookupFunction<_PacketSerialiseC, _PacketSerialiseDart>(
            'cipherbird_packet_serialise',
          ),
      packetDeserialise = lib
          .lookupFunction<_PacketDeserialiseC, _PacketDeserialiseDart>(
            'cipherbird_packet_deserialise',
          ),
      vaultFree = lib.lookupFunction<_VaultFreeC, _VaultFreeDart>(
        'cipherbird_vault_free',
      ),
      asymBundleGenerate = lib
          .lookupFunction<_AsymBundleGenerateC, _AsymBundleGenerateDart>(
            'cipherbird_asym_bundle_generate',
          ),
      asymVaultSeal = lib.lookupFunction<_AsymVaultSealC, _AsymVaultSealDart>(
        'cipherbird_asym_vault_seal',
      ),
      asymVaultOpen = lib.lookupFunction<_AsymVaultOpenC, _AsymVaultOpenDart>(
        'cipherbird_asym_vault_open',
      );

  final _VaultCreateDart vaultCreate;
  final _VaultFromEntropyDart vaultFromEntropy;
  final _VaultSealDart vaultSeal;
  final _VaultSealBoostedDart vaultSealBoosted;
  final _VaultOpenDart vaultOpen;
  final _VaultOpenBoostedDart vaultOpenBoosted;
  final _VaultPublicKeyDart vaultPublicKey;
  final _PacketSerialiseDart packetSerialise;
  final _PacketDeserialiseDart packetDeserialise;
  final _VaultFreeDart vaultFree;
  final _AsymBundleGenerateDart asymBundleGenerate;
  final _AsymVaultSealDart asymVaultSeal;
  final _AsymVaultOpenDart asymVaultOpen;
}
