import 'dart:typed_data';

/// Text as UTF-16 code units narrowed to bytes (ASCII in this app).
Uint8List ascii(String s) => Uint8List.fromList(s.codeUnits);

/// Lower-case hex of [b].
String hexOf(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// Bytes of a hex string.
Uint8List bytesOfHex(String h) => Uint8List.fromList([
  for (var i = 0; i < h.length; i += 2)
    int.parse(h.substring(i, i + 2), radix: 16),
]);

/// Whether two byte lists are equal.
bool same(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

/// Throws unless [cond] holds.
void demand(bool cond, String what) {
  if (!cond) {
    throw StateError(what);
  }
}
