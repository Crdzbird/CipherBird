part of '../../cryptolib.dart';

/// One-call composed recipes (PQ seal, threshold, file-keyed, keyring-backed).
extension SuiteApiPassphraseAndThreshold on SuiteApi {
  /// Keyring-guarded via a passphrase slot.
  Uint8List sealWithKeyringPassphrase(
    Uint8List plaintext,
    Pointer<Void> keyring,
    String passphrase, {
    Uint8List? aad,
  }) => _l.suiteSealWithKeyringPassphrase(
    plaintext,
    keyring,
    passphrase,
    aad: aad,
  );

  Uint8List openWithKeyringPassphrase(
    Uint8List envelope,
    Pointer<Void> keyring,
    String passphrase, {
    Uint8List? aad,
  }) => _l.suiteOpenWithKeyringPassphrase(
    envelope,
    keyring,
    passphrase,
    aad: aad,
  );

  /// EVM address (20 bytes) from a 65-byte uncompressed secp256k1 public key.
  Uint8List evmAddress(Uint8List secp256k1PublicKey) =>
      _l.suiteEvmAddress(secp256k1PublicKey);

  /// Threshold (k-of-n): seal under a fresh master, split it into [n] Shamir
  /// shares of which any [k] reconstruct it. Returns the envelope and the [n]
  /// individual share records; distribute the shares, keep the envelope
  /// anywhere. Open with [openThreshold] using any `k` of the shares.
  (Uint8List envelope, List<Uint8List> shares) sealThreshold(
    Uint8List plaintext,
    int n,
    int k, {
    Uint8List? aad,
  }) => _l.suiteSealThreshold(plaintext, n, k, aad: aad);

  /// Reconstruct the master from any k of the shares and open the envelope.
  Uint8List openThreshold(
    Uint8List envelope,
    List<Uint8List> shares, {
    Uint8List? aad,
  }) => _l.suiteOpenThreshold(envelope, shares, aad: aad);
}
