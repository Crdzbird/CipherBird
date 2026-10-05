part of '../../cryptolib_ffi.dart';

/// `List<int>` -> `Uint8List` without copying when it already is one.
extension CryptoByteList on List<int> {
  /// This list as a [Uint8List] (no copy if it already is one).
  Uint8List get u8 =>
      this is Uint8List ? this as Uint8List : Uint8List.fromList(this);
}
