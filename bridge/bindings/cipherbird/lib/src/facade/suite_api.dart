part of '../cryptolib.dart';

/// One-call composed recipes (PQ seal, threshold, file-keyed, keyring-backed).
extension type SuiteApi(CryptoLib _l) {
  /// Post-quantum message: encapsulate to [recipientKemPublic] and seal under
  /// the shared secret. Secure while EITHER X25519 or ML-KEM-768 holds.
  Uint8List sealPq(
    Uint8List plaintext,
    Uint8List recipientKemPublic, {
    Uint8List? aad,
  }) => _l.suiteSealPq(plaintext, recipientKemPublic, aad: aad);

  /// Like [sealPq] but with the X25519+sntrup761 hybrid KEM (a different
  /// lattice family). [openPq] auto-detects the KEM from the envelope.
  Uint8List sealPqSntrup(
    Uint8List plaintext,
    Uint8List recipientKemPublic, {
    Uint8List? aad,
  }) => _l.suiteSealPqSntrup(plaintext, recipientKemPublic, aad: aad);

  /// Open a [sealPq]/[sealPqSntrup] envelope with the recipient's
  /// hybrid-KEM secret key (KEM chosen from the envelope's suite id).
  Uint8List openPq(
    Uint8List envelope,
    Uint8List recipientKemSecret, {
    Uint8List? aad,
  }) => _l.suiteOpenPq(envelope, recipientKemSecret, aad: aad);

  /// Flagship: post-quantum confidentiality (hybrid KEM) + post-quantum
  /// authenticity (Ed25519+ML-DSA-65). [openSignedPq] returns plaintext
  /// only if the signature verifies.
  Uint8List sealSignedPq(
    Uint8List plaintext,
    Uint8List recipientKemPublic,
    Uint8List signerSigSecret, {
    Uint8List? aad,
  }) => _l.suiteSealSignedPq(
    plaintext,
    recipientKemPublic,
    signerSigSecret,
    aad: aad,
  );

  /// Flagship with the X25519+sntrup761 hybrid KEM.
  Uint8List sealSignedPqSntrup(
    Uint8List plaintext,
    Uint8List recipientKemPublic,
    Uint8List signerSigSecret, {
    Uint8List? aad,
  }) => _l.suiteSealSignedPqSntrup(
    plaintext,
    recipientKemPublic,
    signerSigSecret,
    aad: aad,
  );

  /// Decrypt then verify; a signature mismatch throws and yields no plaintext.
  Uint8List openSignedPq(
    Uint8List envelope,
    Uint8List recipientKemSecret,
    Uint8List signerSigPublic, {
    Uint8List? aad,
  }) => _l.suiteOpenSignedPq(
    envelope,
    recipientKemSecret,
    signerSigPublic,
    aad: aad,
  );

  /// File-as-key: deterministic media entropy from [path] derives the master.
  Uint8List sealWithFile(Uint8List plaintext, String path, {Uint8List? aad}) =>
      _l.suiteSealWithFile(plaintext, path, aad: aad);

  /// Re-derive from the same file and open the envelope.
  Uint8List openWithFile(Uint8List envelope, String path, {Uint8List? aad}) =>
      _l.suiteOpenWithFile(envelope, path, aad: aad);

  /// Keyring-guarded: a device-factor unlock provides the MolecularVault master.
  Uint8List sealWithKeyringDevice(
    Uint8List plaintext,
    Pointer<Void> keyring,
    Uint8List factorKey, {
    Uint8List? aad,
  }) => _l.suiteSealWithKeyringDevice(plaintext, keyring, factorKey, aad: aad);

  Uint8List openWithKeyringDevice(
    Uint8List envelope,
    Pointer<Void> keyring,
    Uint8List factorKey, {
    Uint8List? aad,
  }) => _l.suiteOpenWithKeyringDevice(envelope, keyring, factorKey, aad: aad);
}
