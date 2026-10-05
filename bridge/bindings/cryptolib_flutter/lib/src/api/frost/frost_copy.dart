part of '../../cryptolib.dart';

Uint8List _frostCopy(CryptoBuffer buf) {
  if (buf.data == nullptr || buf.len == 0) {
    return Uint8List(0);
  }
  final out = Uint8List(buf.len);
  out.setAll(0, buf.data.asTypedList(buf.len));
  return out;
}
