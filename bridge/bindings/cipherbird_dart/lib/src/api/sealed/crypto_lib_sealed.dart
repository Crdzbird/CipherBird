part of '../../cipher_bird.dart';

/// Sealed-messaging methods on CipherBird (tier 0=Flagship, 1=Fortress).
extension CipherBirdSealed on CipherBird {
  /// Generate a party's recipient (KEM) + sender (signature) keypairs.
  Identity newIdentity(SealedTier tier) {
    final r = _extractKeyPair(
      _lib.lookupFunction<
        CryptoKeyPair Function(Int32),
        CryptoKeyPair Function(int)
      >('cryptolib_sealed_generate_recipient')(tier.value),
    );
    final s = _extractKeyPair(
      _lib.lookupFunction<
        CryptoKeyPair Function(Int32),
        CryptoKeyPair Function(int)
      >('cryptolib_sealed_generate_sender')(tier.value),
    );
    return Identity(
      this,
      tier,
      r.publicKey,
      r.secretKey,
      s.publicKey,
      s.secretKey,
    );
  }

  /// Read an envelope's public header without any key. Null if unrecognizable.
  SealedInfo? sealedInspect(Uint8List envelope) {
    final pe = _toNative(envelope);
    try {
      final info = _lib
          .lookupFunction<
            CryptoSealedInfo Function(Pointer<Uint8>, Size),
            CryptoSealedInfo Function(Pointer<Uint8>, int)
          >('cryptolib_sealed_inspect')(pe, envelope.length);
      if (info.ok == 0) {
        return null;
      }
      final fp = Uint8List(16);
      for (var i = 0; i < 16; i++) {
        fp[i] = info.fingerprint[i];
      }
      return SealedInfo(
        version: info.version,
        suite: SealedTier.fromSuiteId(info.suite),
        streaming: info.streaming == 1,
        fingerprint: fp,
        kemCiphertextLen: info.kemCiphertextLen,
      );
    } finally {
      if (pe != nullptr) {
        calloc.free(pe);
      }
    }
  }

  /// Whether the envelope is addressed to recipientPublic (fingerprint match).
  bool sealedAddressedTo(Uint8List envelope, Uint8List recipientPublic) {
    final pe = _toNative(envelope), pr = _toNative(recipientPublic);
    try {
      return _lib.lookupFunction<
            Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
            int Function(Pointer<Uint8>, int, Pointer<Uint8>, int)
          >('cryptolib_sealed_addressed_to')(
            pe,
            envelope.length,
            pr,
            recipientPublic.length,
          ) ==
          1;
    } finally {
      if (pe != nullptr) {
        calloc.free(pe);
      }
      if (pr != nullptr) {
        calloc.free(pr);
      }
    }
  }
}
