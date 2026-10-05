part of '../../../cryptolib.dart';

/// Entropy operations.
extension CryptoLibEntropyOpenFromFile on CryptoLib {
  /// One-liner: decrypt a packet using a file as the key.
  Uint8List openFromFile(String path, Packet pkt, String aad) {
    final cpath = path.toNativeUtf8();
    final caad = aad.toNativeUtf8();
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_entropy.openFromFile(cpath, cpkt, caad));
    } finally {
      calloc.free(cpath);
      calloc.free(caad);
      _freePacketNative(cpkt);
    }
  }
}
