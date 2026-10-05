part of '../../cipher_bird.dart';

/// OPAQUE registration record (store server-side) + export key.
final class OpaqueRecord {
  final Uint8List record;
  final Uint8List exportKey;
  OpaqueRecord(this.record, this.exportKey);
}
