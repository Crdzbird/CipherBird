part of '../../cryptolib_ffi.dart';

/// Bytes -> text conversions and the two byte helpers every app ends up writing.
extension CryptoBytes on Uint8List {
  /// Lowercase hex, no prefix.
  String get hex => toHex(this);

  /// Standard base64 (with padding).
  String get base64 => base64Encode(this);

  /// URL-safe base64 without padding - safe in URLs, file names and JSON.
  String get base64Url => base64UrlEncode(this).replaceAll('=', '');

  /// Decode as UTF-8 text. Throws on invalid UTF-8.
  String get text => utf8.decode(this);

  /// Compare in constant time. Use this for tags, MACs and tokens - a plain
  /// `==` / `listEquals` leaks where the first mismatch is.
  bool constantTimeEquals(List<int> other) {
    if (length != other.length) {
      return false;
    }
    var diff = 0;
    for (var i = 0; i < length; i++) {
      diff |= this[i] ^ other[i];
    }
    return diff == 0;
  }

  /// A new buffer holding `this` followed by [other].
  Uint8List concat(List<int> other) => Uint8List(length + other.length)
    ..setRange(0, length, this)
    ..setRange(length, length + other.length, other);

  /// Overwrite with zeros. Call on key material you are done with.
  void wipe() => fillRange(0, length, 0);
}
