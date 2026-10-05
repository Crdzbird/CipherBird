part of '../../cryptolib.dart';

/// Layered vaults: Vault, asymmetric Vault and MolecularVault.
extension VaultApiMolecularOpenWithKey on VaultApi {
  /// Open a raw-key-sealed envelope.
  Uint8List molecularOpenWithKey(
    Uint8List envelope,
    Uint8List masterKey, {
    Uint8List? aad,
  }) => _l.molecularOpenWithKey(envelope, masterKey, aad: aad);
}
