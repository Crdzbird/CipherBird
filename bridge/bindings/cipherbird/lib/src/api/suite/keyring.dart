part of '../../cryptolib.dart';

/// Suite - one-call advanced combinations.
///
/// A high-level facade that composes hybrid KEM, hybrid signatures,
/// MolecularVault, media entropy, keyring, Shamir and Keccak into single calls.
/// Every seal is authenticated and fails closed; the post-quantum envelopes are
/// self-describing (they carry the KEM ciphertext), so a recipient needs only
/// their long-term secret key. Requires the native library built with OpenSSL
/// and post-quantum support.
extension CryptoLibSuiteKeyring on CryptoLib {
  /// Keyring-guarded: a device-factor unlock provides the MolecularVault master.
  Uint8List suiteSealWithKeyringDevice(
    Uint8List plaintext,
    Pointer<Void> keyring,
    Uint8List factorKey, {
    Uint8List? aad,
  }) => _suiteKeyringFactor(
    'cryptolib_suite_seal_with_keyring_device',
    plaintext,
    keyring,
    factorKey,
    aad,
  );

  Uint8List suiteOpenWithKeyringDevice(
    Uint8List envelope,
    Pointer<Void> keyring,
    Uint8List factorKey, {
    Uint8List? aad,
  }) => _suiteKeyringFactor(
    'cryptolib_suite_open_with_keyring_device',
    envelope,
    keyring,
    factorKey,
    aad,
  );

  /// Keyring-guarded via a passphrase slot.
  Uint8List suiteSealWithKeyringPassphrase(
    Uint8List plaintext,
    Pointer<Void> keyring,
    String passphrase, {
    Uint8List? aad,
  }) => _suiteKeyringPass(
    'cryptolib_suite_seal_with_keyring_passphrase',
    plaintext,
    keyring,
    passphrase,
    aad,
  );

  Uint8List suiteOpenWithKeyringPassphrase(
    Uint8List envelope,
    Pointer<Void> keyring,
    String passphrase, {
    Uint8List? aad,
  }) => _suiteKeyringPass(
    'cryptolib_suite_open_with_keyring_passphrase',
    envelope,
    keyring,
    passphrase,
    aad,
  );

  /// EVM address (20 bytes) from a 65-byte uncompressed secp256k1 public key.
  Uint8List suiteEvmAddress(Uint8List secp256k1PublicKey) {
    final pk = _toNative(secp256k1PublicKey);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int)
        >('cryptolib_suite_evm_address')(pk, secp256k1PublicKey.length),
      );
    } finally {
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }
}
