part of '../cipher_bird.dart';

extension _MarshalStructs on CipherBird {
  Packet _extractPacket(CryptoPacket cp, Pointer<Pointer<Utf8>> errPtr) {
    if (errPtr.value != nullptr) {
      final msg = errPtr.value.toDartString();
      _core.strFree(errPtr.value);
      throw Exception(msg);
    }
    return Packet(
      ciphertext: _copyBuf(cp.ciphertext),
      signature: _copyBuf(cp.signature),
      kdfSalt: _copyBuf(cp.kdfSalt),
    );
  }

  Pointer<CryptoPacket> _packetToNative(Packet pkt) {
    final cpkt = calloc<CryptoPacket>();
    final ct = _toNative(pkt.ciphertext);
    final sig = _toNative(pkt.signature);
    final salt = _toNative(pkt.kdfSalt);
    cpkt.ref.ciphertext.data = ct;
    cpkt.ref.ciphertext.len = pkt.ciphertext.length;
    cpkt.ref.signature.data = sig;
    cpkt.ref.signature.len = pkt.signature.length;
    cpkt.ref.kdfSalt.data = salt;
    cpkt.ref.kdfSalt.len = pkt.kdfSalt.length;
    return cpkt;
  }

  void _freePacketNative(Pointer<CryptoPacket> cpkt) {
    if (cpkt.ref.ciphertext.data != nullptr) {
      calloc.free(cpkt.ref.ciphertext.data);
    }
    if (cpkt.ref.signature.data != nullptr) {
      calloc.free(cpkt.ref.signature.data);
    }
    if (cpkt.ref.kdfSalt.data != nullptr) {
      calloc.free(cpkt.ref.kdfSalt.data);
    }
    calloc.free(cpkt);
  }

  KeyPairResult _extractKeyPair(CryptoKeyPair kp) {
    return KeyPairResult(
      publicKey: _copyBuf(kp.publicKey),
      secretKey: _copyBuf(kp.secretKey),
    );
  }

  AsymBundleResult _extractBundle(CryptoAsymBundle ab) {
    return AsymBundleResult(
      boxPublic: _copyBuf(ab.boxPublic),
      boxSecret: _copyBuf(ab.boxSecret),
      signPublic: _copyBuf(ab.signPublic),
      signSecret: _copyBuf(ab.signSecret),
    );
  }

  /// Marshal a list of byte buffers into the C `const uint8_t* const*` +
  /// `const size_t*` array pair. Release both (and the element buffers) with
  /// [_freeNativeList].
}
