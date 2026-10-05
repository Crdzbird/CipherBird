part of '../cipher_bird.dart';

/// AsymmetricVault operations.
extension CipherBirdAsymmetricVault on CipherBird {
  /// Generate a full asymmetric key bundle (X25519 + Ed25519).
  AsymBundleResult asymBundleGenerate() =>
      _extractBundle(_vault.asymBundleGenerate());

  /// Asymmetric vault seal: sender encrypts for recipient with signature.
  Packet asymVaultSeal(
    AsymBundleResult sender,
    Uint8List recipientBoxPub,
    Uint8List plaintext,
    String aad,
  ) {
    final csender = calloc<CipherBirdAsymBundle>();
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
      final cp = _vault.asymVaultSeal(
        csender,
        prpub,
        recipientBoxPub.length,
        pp,
        plaintext.length,
        caad,
        errPtr,
      );
      return _extractPacket(cp, errPtr);
    } finally {
      calloc.free(sbp);
      calloc.free(sbs);
      calloc.free(ssp);
      calloc.free(sss);
      calloc.free(csender);
      if (prpub != nullptr) {
        calloc.free(prpub);
      }
      if (pp != nullptr) {
        calloc.free(pp);
      }
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }
}
