import 'dart:typed_data';

/// What the platform produced to attest a hardware key, for a server to
/// verify. Nothing here is stored in the keyring envelope.
final class HardwareAttestation {
  const HardwareAttestation({
    required this.kind,
    required this.keyId,
    required this.document,
    required this.publicKey,
  });

  /// Which scheme produced [document].
  final AttestationKind kind;

  /// The attested key's identifier on the platform.
  final String keyId;

  /// App Attest: the attestation object (CBOR) over
  /// SHA-256(challenge || Secure Enclave public key). Android: the key
  /// attestation certificate chain as length-prefixed DER records.
  final Uint8List document;

  /// The attested public key: X9.63 on Apple, X.509 DER on Android.
  final Uint8List publicKey;
}

/// The attestation scheme behind a [HardwareAttestation].
enum AttestationKind {
  /// Apple App Attest.
  appAttest,

  /// Android key attestation.
  androidKeyAttestation,
}
