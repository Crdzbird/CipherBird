part of '../cryptolib.dart';

final class _NativeVault {
  _NativeVault(DynamicLibrary lib)
    : vaultCreate = lib.lookupFunction<_VaultCreateC, _VaultCreateDart>(
        'cryptolib_vault_create',
      ),
      vaultFromEntropy = lib
          .lookupFunction<_VaultFromEntropyC, _VaultFromEntropyDart>(
            'cryptolib_vault_from_entropy',
          ),
      vaultSeal = lib.lookupFunction<_VaultSealC, _VaultSealDart>(
        'cryptolib_vault_seal',
      ),
      vaultSealBoosted = lib
          .lookupFunction<_VaultSealBoostedC, _VaultSealBoostedDart>(
            'cryptolib_vault_seal_boosted',
          ),
      vaultOpen = lib.lookupFunction<_VaultOpenC, _VaultOpenDart>(
        'cryptolib_vault_open',
      ),
      vaultOpenBoosted = lib
          .lookupFunction<_VaultOpenBoostedC, _VaultOpenBoostedDart>(
            'cryptolib_vault_open_boosted',
          ),
      vaultPublicKey = lib
          .lookupFunction<_VaultPublicKeyC, _VaultPublicKeyDart>(
            'cryptolib_vault_public_key',
          ),
      packetSerialise = lib
          .lookupFunction<_PacketSerialiseC, _PacketSerialiseDart>(
            'cryptolib_packet_serialise',
          ),
      packetDeserialise = lib
          .lookupFunction<_PacketDeserialiseC, _PacketDeserialiseDart>(
            'cryptolib_packet_deserialise',
          ),
      vaultFree = lib.lookupFunction<_VaultFreeC, _VaultFreeDart>(
        'cryptolib_vault_free',
      ),
      asymBundleGenerate = lib
          .lookupFunction<_AsymBundleGenerateC, _AsymBundleGenerateDart>(
            'cryptolib_asym_bundle_generate',
          ),
      asymVaultSeal = lib.lookupFunction<_AsymVaultSealC, _AsymVaultSealDart>(
        'cryptolib_asym_vault_seal',
      ),
      asymVaultOpen = lib.lookupFunction<_AsymVaultOpenC, _AsymVaultOpenDart>(
        'cryptolib_asym_vault_open',
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
