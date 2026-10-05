part of '../../cryptolib.dart';

/// Encrypting stream: preamble() once, push() each chunk, finalize() for the last
/// chunk + signed trailer; close() when done.
final class SealedStreamSealer {
  final CryptoLib _cl;
  Pointer<Void> _h;
  SealedStreamSealer(this._cl, this._h);
  Uint8List preamble() => _cl._sealedSealerPreamble(_h);
  Uint8List push(Uint8List chunk) => _cl._sealedSealerPush(_h, chunk);
  (Uint8List ciphertext, Uint8List trailer) finalize([Uint8List? last]) =>
      _cl._sealedSealerFinalize(_h, last);
  void close() {
    if (_h != nullptr) {
      _cl._sealedSealerFree(_h);
      _h = nullptr;
    }
  }
}
