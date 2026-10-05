part of '../../cryptolib.dart';

/// OPAQUE server login message 2 + opaque server state.
final class OpaqueKe2 {
  final Uint8List ke2;
  final Uint8List serverState;
  OpaqueKe2(this.ke2, this.serverState);
}
