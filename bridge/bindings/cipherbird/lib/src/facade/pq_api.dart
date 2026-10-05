part of '../cipher_bird.dart';

/// Post-quantum algorithms, grouped by scheme.
extension type PqApi(CipherBird _l) {
  /// ML-KEM (FIPS 203) key encapsulation.
  PqMlKemApi get mlKem => PqMlKemApi(_l);

  /// ML-DSA (FIPS 204) signatures.
  PqMlDsaApi get mlDsa => PqMlDsaApi(_l);

  /// SLH-DSA (FIPS 205) hash-based signatures.
  PqSlhDsaApi get slhDsa => PqSlhDsaApi(_l);

  /// X25519 + ML-KEM-768 hybrid KEM.
  PqHybridKemApi get hybridKem => PqHybridKemApi(_l);

  /// Ed25519 + ML-DSA-65 hybrid signatures.
  PqHybridSigApi get hybridSig => PqHybridSigApi(_l);

  /// X25519 + sntrup761 hybrid KEM (a second lattice family).
  PqSntrupApi get sntrup => PqSntrupApi(_l);
}
