part of '../cipher_bird.dart';

/// Text -> bytes conversions. `'hello'.bytes`, `'ab12'.hexBytes`, `'aGk='.base64Bytes`.
extension CipherBirdText on String {
  /// UTF-8 bytes of this string.
  Uint8List get bytes => Uint8List.fromList(utf8.encode(this));

  /// Decode this hex string (case-insensitive, no `0x`) into bytes.
  Uint8List get hexBytes => fromHex(this);

  /// Decode this base64 (standard or URL-safe) string into bytes.
  Uint8List get base64Bytes => base64Decode(base64.normalize(this));
}
