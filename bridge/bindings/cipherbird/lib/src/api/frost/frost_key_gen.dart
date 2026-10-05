part of '../../cipher_bird.dart';

/// FROST trusted-dealer output: the group public key plus per-participant
/// shares. Share i (0-based) has FROST identifier i+1. Keep [secretShares]
/// private; distribute one to each participant.
final class FrostKeyGen {
  final Uint8List groupPublicKey;
  final List<Uint8List> secretShares;
  final List<Uint8List> publicShares;
  FrostKeyGen(this.groupPublicKey, this.secretShares, this.publicShares);
}
