part of '../../cipher_bird.dart';

/// OPAQUE client login message 1 + opaque client state.
final class OpaqueKe1 {
  final Uint8List ke1;
  final Uint8List clientState;
  OpaqueKe1(this.ke1, this.clientState);
}
