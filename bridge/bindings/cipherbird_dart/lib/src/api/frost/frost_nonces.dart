part of '../../cryptolib.dart';

/// A participant's secret round-1 nonces (never share these).
final class FrostNonces {
  final Uint8List hiding;
  final Uint8List binding;
  FrostNonces(this.hiding, this.binding);
}
