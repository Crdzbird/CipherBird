part of '../../cipher_bird.dart';

/// An established one-directional HPKE context. Stateful; close() when done.
final class HpkeContext {
  final CipherBird _cl;
  Pointer<Void> _h;
  HpkeContext(this._cl, this._h);

  /// Sender: AEAD-seal the next message (advances the sequence).
  Uint8List seal(Uint8List plaintext, {Uint8List? aad}) =>
      _cl._hpkeMsg('cryptolib_hpke_seal', _h, plaintext, aad);

  /// Receiver: AEAD-open the next message (advances the sequence).
  Uint8List open(Uint8List ciphertext, {Uint8List? aad}) =>
      _cl._hpkeMsg('cryptolib_hpke_open', _h, ciphertext, aad);

  /// Derive a length-byte secret bound to this context (RFC 9180 §5.3).
  Uint8List export(Uint8List exporterContext, int length) =>
      _cl._hpkeExport(_h, exporterContext, length);

  void close() {
    if (_h != nullptr) {
      _cl._hpkeFree(_h);
      _h = nullptr;
    }
  }
}
