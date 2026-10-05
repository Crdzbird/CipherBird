part of '../../cryptolib_ffi.dart';

/// Random bytes and explicitly-seeded generators.
extension type RngApi(CryptoLib _l) {
  /// Generate n cryptographically secure random bytes.
  Uint8List bytes(int n) => _l.randomBytes(n);

  /// Instantiate an HMAC-DRBG from entropy (>= 32 bytes) + optional nonce +
  /// personalization. Call [Drbg.close] when done.
  Drbg drbg(Uint8List entropy,
          [Uint8List? nonce, Uint8List? personalization]) =>
      _l.drbgInstantiate(entropy, nonce, personalization);

  /// Create a new (unseeded) Fortuna pool. Call [Fortuna.close] when done.
  Fortuna fortuna() => _l.fortunaNew();
}
