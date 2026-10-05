part of '../../cipher_bird.dart';

/// AsymmetricVault operations.
extension CipherBirdAsymmetricVaultOpen on CipherBird {
  /// Asymmetric vault open: recipient decrypts and verifies.
  Uint8List asymVaultOpen(
    Packet pkt,
    AsymBundleResult recipient,
    Uint8List senderSignPub,
    String aad,
  ) {
    final cpkt = _packetToNative(pkt);

    final crecip = calloc<CryptoAsymBundle>();
    final rbp = _toNative(recipient.boxPublic);
    final rbs = _toNative(recipient.boxSecret);
    final rsp = _toNative(recipient.signPublic);
    final rss = _toNative(recipient.signSecret);
    crecip.ref.boxPublic.data = rbp;
    crecip.ref.boxPublic.len = recipient.boxPublic.length;
    crecip.ref.boxSecret.data = rbs;
    crecip.ref.boxSecret.len = recipient.boxSecret.length;
    crecip.ref.signPublic.data = rsp;
    crecip.ref.signPublic.len = recipient.signPublic.length;
    crecip.ref.signSecret.data = rss;
    crecip.ref.signSecret.len = recipient.signSecret.length;

    final psspub = _toNative(senderSignPub);
    final caad = aad.toNativeUtf8();

    try {
      return _checkBufResult(
        _vault.asymVaultOpen(cpkt, crecip, psspub, senderSignPub.length, caad),
      );
    } finally {
      _freePacketNative(cpkt);
      calloc.free(rbp);
      calloc.free(rbs);
      calloc.free(rsp);
      calloc.free(rss);
      calloc.free(crecip);
      if (psspub != nullptr) {
        calloc.free(psspub);
      }
      calloc.free(caad);
    }
  }
}
