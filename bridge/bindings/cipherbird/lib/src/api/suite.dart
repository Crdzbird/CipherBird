part of '../cryptolib.dart';

/// Suite - one-call advanced combinations.
///
/// A high-level facade that composes hybrid KEM, hybrid signatures,
/// MolecularVault, media entropy, keyring, Shamir and Keccak into single calls.
/// Every seal is authenticated and fails closed; the post-quantum envelopes are
/// self-describing (they carry the KEM ciphertext), so a recipient needs only
/// their long-term secret key. Requires the native library built with OpenSSL
/// and post-quantum support.
extension CryptoLibSuite on CryptoLib {
  /// Post-quantum message: encapsulate to [recipientKemPublic] and seal under
  /// the shared secret. Secure while EITHER X25519 or ML-KEM-768 holds.
  Uint8List suiteSealPq(
    Uint8List plaintext,
    Uint8List recipientKemPublic, {
    Uint8List? aad,
  }) =>
      _suiteBuf('cryptolib_suite_seal_pq', plaintext, recipientKemPublic, aad);

  /// Like [suiteSealPq] but with the X25519+sntrup761 hybrid KEM (a different
  /// lattice family). [suiteOpenPq] auto-detects the KEM from the envelope.
  Uint8List suiteSealPqSntrup(
    Uint8List plaintext,
    Uint8List recipientKemPublic, {
    Uint8List? aad,
  }) => _suiteBuf(
    'cryptolib_suite_seal_pq_sntrup',
    plaintext,
    recipientKemPublic,
    aad,
  );

  /// Open a [suiteSealPq]/[suiteSealPqSntrup] envelope with the recipient's
  /// hybrid-KEM secret key (KEM chosen from the envelope's suite id).
  Uint8List suiteOpenPq(
    Uint8List envelope,
    Uint8List recipientKemSecret, {
    Uint8List? aad,
  }) => _suiteBuf('cryptolib_suite_open_pq', envelope, recipientKemSecret, aad);

  /// Flagship: post-quantum confidentiality (hybrid KEM) + post-quantum
  /// authenticity (Ed25519+ML-DSA-65). [suiteOpenSignedPq] returns plaintext
  /// only if the signature verifies.
  Uint8List suiteSealSignedPq(
    Uint8List plaintext,
    Uint8List recipientKemPublic,
    Uint8List signerSigSecret, {
    Uint8List? aad,
  }) => _suiteBuf3(
    'cryptolib_suite_seal_signed_pq',
    plaintext,
    recipientKemPublic,
    signerSigSecret,
    aad,
  );

  /// Flagship with the X25519+sntrup761 hybrid KEM.
  Uint8List suiteSealSignedPqSntrup(
    Uint8List plaintext,
    Uint8List recipientKemPublic,
    Uint8List signerSigSecret, {
    Uint8List? aad,
  }) => _suiteBuf3(
    'cryptolib_suite_seal_signed_pq_sntrup',
    plaintext,
    recipientKemPublic,
    signerSigSecret,
    aad,
  );

  /// Decrypt then verify; a signature mismatch throws and yields no plaintext.
  Uint8List suiteOpenSignedPq(
    Uint8List envelope,
    Uint8List recipientKemSecret,
    Uint8List signerSigPublic, {
    Uint8List? aad,
  }) => _suiteBuf3(
    'cryptolib_suite_open_signed_pq',
    envelope,
    recipientKemSecret,
    signerSigPublic,
    aad,
  );

  /// File-as-key: deterministic media entropy from [path] derives the master.
  Uint8List suiteSealWithFile(
    Uint8List plaintext,
    String path, {
    Uint8List? aad,
  }) => _suiteFile('cryptolib_suite_seal_with_file', plaintext, path, aad);

  /// Re-derive from the same file and open the envelope.
  Uint8List suiteOpenWithFile(
    Uint8List envelope,
    String path, {
    Uint8List? aad,
  }) => _suiteFile('cryptolib_suite_open_with_file', envelope, path, aad);
}
