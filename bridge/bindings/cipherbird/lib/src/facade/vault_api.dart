part of '../cryptolib.dart';

/// Layered vaults: Vault, asymmetric Vault and MolecularVault.
extension type VaultApi(CryptoLib _l) {
  /// Create a vault from a 32-byte master key.
  Pointer<Void> vaultCreate(
    Uint8List masterKey, {
    KdfPreset kdfPreset = KdfPreset.interactive,
  }) => _l.vaultCreate(masterKey, kdfPreset: kdfPreset);

  /// Create a vault from an entropy handle.
  Pointer<Void> vaultFromEntropy(
    Pointer<Void> entropy, {
    KdfPreset kdf = KdfPreset.interactive,
  }) => _l.vaultFromEntropy(entropy, kdf: kdf);

  /// Seal plaintext through the vault pipeline.
  Packet vaultSeal(Pointer<Void> vault, Uint8List plaintext, String aad) =>
      _l.vaultSeal(vault, plaintext, aad);

  /// Seal with entropy boost (two-factor).
  Packet vaultSealBoosted(
    Pointer<Void> vault,
    Uint8List plaintext,
    String aad,
    Pointer<Void> boost,
  ) => _l.vaultSealBoosted(vault, plaintext, aad, boost);

  /// Open a vault packet.
  Uint8List vaultOpen(Pointer<Void> vault, Packet pkt, String aad) =>
      _l.vaultOpen(vault, pkt, aad);

  /// Open with entropy boost.
  Uint8List vaultOpenBoosted(
    Pointer<Void> vault,
    Packet pkt,
    String aad,
    Pointer<Void> boost,
  ) => _l.vaultOpenBoosted(vault, pkt, aad, boost);

  /// Get the vault's Ed25519 public key.
  Uint8List vaultPublicKey(Pointer<Void> vault) => _l.vaultPublicKey(vault);

  /// Serialise a packet to flat bytes.
  Uint8List packetSerialise(Packet pkt) => _l.packetSerialise(pkt);

  /// Deserialise flat bytes to a packet.
  Packet packetDeserialise(Uint8List data) => _l.packetDeserialise(data);

  /// Free a vault handle.
  void vaultFree(Pointer<Void> vault) => _l.vaultFree(vault);

  /// Generate a full asymmetric key bundle (X25519 + Ed25519).
  AsymBundleResult asymBundleGenerate() => _l.asymBundleGenerate();

  /// Asymmetric vault seal: sender encrypts for recipient with signature.
  Packet asymVaultSeal(
    AsymBundleResult sender,
    Uint8List recipientBoxPub,
    Uint8List plaintext,
    String aad,
  ) => _l.asymVaultSeal(sender, recipientBoxPub, plaintext, aad);

  /// Asymmetric vault open: recipient decrypts and verifies.
  Uint8List asymVaultOpen(
    Packet pkt,
    AsymBundleResult recipient,
    Uint8List senderSignPub,
    String aad,
  ) => _l.asymVaultOpen(pkt, recipient, senderSignPub, aad);

  /// Seal [plaintext] under a [passphrase]. [ops]/[mem] are the Argon2id work
  /// factors; pass 0 for either to use the library's SENSITIVE preset. Raise
  /// [mem] toward 1 << 30 (1 GiB) to make password guessing far costlier. The
  /// returned envelope is self-describing (carries the salt and parameters).
  Uint8List molecularSeal(
    Uint8List plaintext,
    String passphrase, {
    Uint8List? aad,
    int ops = 0,
    int mem = 0,
  }) => _l.molecularSeal(plaintext, passphrase, aad: aad, ops: ops, mem: mem);

  /// Open a passphrase-sealed envelope. A wrong passphrase, wrong [aad], or any
  /// tampering throws (fails closed) rather than returning garbage.
  Uint8List molecularOpen(
    Uint8List envelope,
    String passphrase, {
    Uint8List? aad,
  }) => _l.molecularOpen(envelope, passphrase, aad: aad);

  /// Seal under a 32-byte full-entropy [masterKey] (e.g. a hybrid-KEM shared
  /// secret). No Argon2id is applied - the key is assumed to be full-entropy.
  Uint8List molecularSealWithKey(
    Uint8List plaintext,
    Uint8List masterKey, {
    Uint8List? aad,
  }) => _l.molecularSealWithKey(plaintext, masterKey, aad: aad);
}
