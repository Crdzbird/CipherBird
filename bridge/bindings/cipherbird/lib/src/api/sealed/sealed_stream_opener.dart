part of '../../cipher_bird.dart';

/// Decrypting stream: pull() each chunk (isFinal on the last), then finalize()
/// to verify the sender signature over the whole stream.
final class SealedStreamOpener {
  final CipherBird _cl;
  Pointer<Void> _h;
  SealedStreamOpener(this._cl, this._h);
  (Uint8List plaintext, bool isFinal) pull(Uint8List ct) =>
      _cl._sealedOpenerPull(_h, ct);
  void finalize(Uint8List trailer) => _cl._sealedOpenerFinalize(_h, trailer);
  void close() {
    if (_h != nullptr) {
      _cl._sealedOpenerFree(_h);
      _h = nullptr;
    }
  }
}
