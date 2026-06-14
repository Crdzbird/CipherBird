part of '../cryptolib.dart';

/// AsymmetricVault operations.
extension CryptoLibAsymmetricVault on CryptoLib {
  // ── Asymmetric Vault ──────────────────────────────────────────────────────

  /// Generate a full asymmetric key bundle (X25519 + Ed25519).
  AsymBundleResult asymBundleGenerate() => _extractBundle(_asymBundleGenerate());

  /// Asymmetric vault seal: sender encrypts for recipient with signature.
  Packet asymVaultSeal(AsymBundleResult sender, Uint8List recipientBoxPub, Uint8List plaintext, String aad) {
    final csender = calloc<CryptoAsymBundle>();
    final sbp = _toNative(sender.boxPublic);
    final sbs = _toNative(sender.boxSecret);
    final ssp = _toNative(sender.signPublic);
    final sss = _toNative(sender.signSecret);
    csender.ref.boxPublic.data = sbp;
    csender.ref.boxPublic.len = sender.boxPublic.length;
    csender.ref.boxSecret.data = sbs;
    csender.ref.boxSecret.len = sender.boxSecret.length;
    csender.ref.signPublic.data = ssp;
    csender.ref.signPublic.len = sender.signPublic.length;
    csender.ref.signSecret.data = sss;
    csender.ref.signSecret.len = sender.signSecret.length;

    final prpub = _toNative(recipientBoxPub);
    final pp = _toNative(plaintext);
    final caad = aad.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();

    try {
      final cp = _asymVaultSeal(csender, prpub, recipientBoxPub.length, pp, plaintext.length, caad, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      calloc.free(sbp);
      calloc.free(sbs);
      calloc.free(ssp);
      calloc.free(sss);
      calloc.free(csender);
      if (prpub != nullptr) calloc.free(prpub);
      if (pp != nullptr) calloc.free(pp);
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }

  /// Asymmetric vault open: recipient decrypts and verifies.
  Uint8List asymVaultOpen(Packet pkt, AsymBundleResult recipient, Uint8List senderSignPub, String aad) {
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
      return _checkBufResult(_asymVaultOpen(cpkt, crecip, psspub, senderSignPub.length, caad));
    } finally {
      _freePacketNative(cpkt);
      calloc.free(rbp);
      calloc.free(rbs);
      calloc.free(rsp);
      calloc.free(rss);
      calloc.free(crecip);
      if (psspub != nullptr) calloc.free(psspub);
      calloc.free(caad);
    }
  }

}
