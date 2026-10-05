part of '../../cipher_bird.dart';

/// OPAQUE client login message 3 + the session key + export key.
final class OpaqueKe3 {
  final Uint8List ke3;
  final Uint8List sessionKey;
  final Uint8List exportKey;
  OpaqueKe3(this.ke3, this.sessionKey, this.exportKey);
}
