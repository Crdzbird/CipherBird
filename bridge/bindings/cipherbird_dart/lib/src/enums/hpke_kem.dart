part of '../cipher_bird.dart';

/// HPKE KEM selector. Values are the IANA HPKE KEM identifiers.
enum HpkeKem {
  /// DHKEM(X25519, HKDF-SHA256): all four HPKE modes.
  dhkemX25519(0x0020),

  /// ML-KEM-768 (draft-ietf-hpke-pq): base and psk modes, 64-byte seed secret keys.
  mlKem768(0x0041),

  /// X-Wing (draft-connolly-cfrg-xwing-kem): base and psk modes, the bank default.
  xWing(0x647A);

  const HpkeKem(this.value);

  /// IANA KEM identifier.
  final int value;
}
