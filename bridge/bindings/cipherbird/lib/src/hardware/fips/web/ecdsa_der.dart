import 'dart:typed_data';

/// ECDSA signature forms: WebCrypto speaks raw `r || s`, the device
/// modules and the engine speak DER.
final class EcdsaDer {
  const EcdsaDer();

  Uint8List fromRaw(Uint8List raw) {
    final r = _integer(raw.sublist(0, raw.length ~/ 2));
    final s = _integer(raw.sublist(raw.length ~/ 2));
    return Uint8List.fromList([0x30, r.length + s.length, ...r, ...s]);
  }

  Uint8List toRaw(Uint8List der, int size) {
    var i = 2;
    final out = Uint8List(size * 2);
    for (var part = 0; part < 2; part++) {
      if (der[i] != 0x02) {
        throw const FormatException('not a DER ECDSA signature');
      }
      final len = der[i + 1];
      var value = der.sublist(i + 2, i + 2 + len);
      while (value.length > size && value[0] == 0) {
        value = value.sublist(1);
      }
      out.setRange(
        part * size + size - value.length,
        part * size + size,
        value,
      );
      i += 2 + len;
    }
    return out;
  }

  List<int> _integer(Uint8List v) {
    var start = 0;
    while (start < v.length - 1 && v[start] == 0) {
      start++;
    }
    final body = v.sublist(start);
    final padded = body[0] & 0x80 != 0 ? [0, ...body] : body;
    return [0x02, padded.length, ...padded];
  }
}
