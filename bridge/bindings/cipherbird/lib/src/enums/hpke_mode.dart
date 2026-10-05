part of '../cryptolib.dart';

/// HPKE mode. Determines which of sender authentication and pre-shared-key
/// authentication are in play.
enum HpkeMode {
  /// Recipient authentication only.
  base(0),

  /// Adds a pre-shared key.
  psk(1),

  /// Adds sender authentication via a static sender key.
  auth(2),

  /// Both a pre-shared key and sender authentication.
  authPsk(3);

  const HpkeMode(this.value);

  /// RFC 9180 mode identifier.
  final int value;

  /// This mode requires a `psk` and `pskId`.
  bool get requiresPsk => this == HpkeMode.psk || this == HpkeMode.authPsk;

  /// This mode requires a static sender key (`skS` when sealing, `pkS` when
  /// opening).
  bool get requiresSenderKey =>
      this == HpkeMode.auth || this == HpkeMode.authPsk;
}
