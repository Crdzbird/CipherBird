part of '../cipher_bird.dart';

/// Secret material with a definite end of life. [wipe] overwrites the bytes
/// with zeros and every later access throws, so a key or password copy
/// cannot linger on the Dart heap unnoticed. If the object is collected
/// before [wipe], the bytes are zeroed by a finalizer on a best-effort basis.
///
/// ```dart
/// final secret = SecretBytes.copy(sharedSecret);
/// final key = secret.use((bytes) => lib.hkdfDerive(bytes, info: info));
/// secret.wipe();
/// ```
final class SecretBytes {
  SecretBytes._(this._bytes) {
    _finalizer.attach(this, _bytes, detach: this);
  }

  /// Takes ownership of [bytes] without copying; wipe them through this.
  factory SecretBytes.take(Uint8List bytes) => SecretBytes._(bytes);

  /// A private copy of [bytes]; the caller still owns and should wipe the
  /// original.
  factory SecretBytes.copy(List<int> bytes) =>
      SecretBytes._(Uint8List.fromList(bytes));

  static final Finalizer<Uint8List> _finalizer = Finalizer(_zero);

  static void _zero(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);

  final Uint8List _bytes;

  bool _wiped = false;

  /// Whether [wipe] ran.
  bool get isWiped => _wiped;

  /// Number of bytes.
  int get length => _bytes.length;

  /// The live bytes, not a copy. Throws [StateError] after [wipe].
  Uint8List get bytes {
    if (_wiped) {
      throw StateError('cipherbird: this secret was wiped');
    }
    return _bytes;
  }

  /// An independent copy; wipe it when done.
  Uint8List copy() => Uint8List.fromList(bytes);

  /// Runs [action] over the live bytes.
  T use<T>(T Function(Uint8List bytes) action) => action(bytes);

  /// Overwrites the bytes with zeros. Idempotent.
  void wipe() {
    if (_wiped) {
      return;
    }
    _wiped = true;
    _zero(_bytes);
    _finalizer.detach(this);
  }
}
