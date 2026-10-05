part of '../../cryptolib.dart';

/// A participant's public round-1 commitment.
final class FrostCommitment {
  final int identifier;
  final Uint8List hiding;
  final Uint8List binding;
  FrostCommitment(this.identifier, this.hiding, this.binding);
}
