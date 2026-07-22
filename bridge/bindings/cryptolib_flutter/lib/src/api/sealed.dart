part of '../cryptolib.dart';

// ── Flagship / Fortress — state-of-the-art sealed messaging ───────────────────
// Two assurance tiers of one construction (encapsulate → sign-then-encrypt inside
// a key-committing cascade, recipient-bound, auth-first). A self-contained,
// drop-in messaging layer. tier 0 = Flagship, 1 = Fortress.

/// Assurance tier for Flagship/Fortress sealed messaging (index 0 / 1).
enum SealedTier { flagship, fortress }

/// Public metadata carried by a sealed envelope (no secrets).
class SealedInfo {
  final int version;
  final int suite; // 1 = Flagship, 2 = Fortress
  final bool streaming;
  final Uint8List fingerprint; // BLAKE2b-128 of the recipient public key
  final int kemCiphertextLen;
  SealedInfo({required this.version, required this.suite, required this.streaming,
      required this.fingerprint, required this.kemCiphertextLen});
}

/// A party's keypairs — recipient (KEM) for receiving, sender (signature) for
/// signing. The config/setup handle for the sealed-messaging API.
class Identity {
  final CryptoLib lib;
  final SealedTier tier;
  final Uint8List recipientPublic, recipientSecret, senderPublic, senderSecret;
  Identity(this.lib, this.tier, this.recipientPublic, this.recipientSecret,
      this.senderPublic, this.senderSecret);

  Uint8List seal(Uint8List plaintext, Uint8List recipientPublic, {Uint8List? aad, Uint8List? purpose}) =>
      lib.sealedSeal(tier, plaintext, recipientPublic, senderSecret, aad: aad, purpose: purpose);
  Uint8List open(Uint8List envelope, Uint8List senderPublic, {Uint8List? aad, Uint8List? purpose}) =>
      lib.sealedOpen(tier, envelope, recipientSecret, recipientPublic, senderPublic, aad: aad, purpose: purpose);
  SealedStreamSealer newStreamSealer(Uint8List recipientPublic, {Uint8List? purpose}) =>
      lib.sealedSealerBegin(tier, recipientPublic, senderSecret, purpose: purpose);
  SealedStreamOpener newStreamOpener(Uint8List preamble, Uint8List senderPublic, {Uint8List? purpose}) =>
      lib.sealedOpenerBegin(tier, preamble, recipientSecret, recipientPublic, senderPublic, purpose: purpose);
}

/// Encrypting stream: preamble() once, push() each chunk, finalize() for the last
/// chunk + signed trailer; close() when done.
class SealedStreamSealer {
  final CryptoLib _cl;
  Pointer<Void> _h;
  SealedStreamSealer(this._cl, this._h);
  Uint8List preamble() => _cl._sealedSealerPreamble(_h);
  Uint8List push(Uint8List chunk) => _cl._sealedSealerPush(_h, chunk);
  (Uint8List ciphertext, Uint8List trailer) finalize([Uint8List? last]) => _cl._sealedSealerFinalize(_h, last);
  void close() { if (_h != nullptr) { _cl._sealedSealerFree(_h); _h = nullptr; } }
}

/// Decrypting stream: pull() each chunk (isFinal on the last), then finalize()
/// to verify the sender signature over the whole stream.
class SealedStreamOpener {
  final CryptoLib _cl;
  Pointer<Void> _h;
  SealedStreamOpener(this._cl, this._h);
  (Uint8List plaintext, bool isFinal) pull(Uint8List ct) => _cl._sealedOpenerPull(_h, ct);
  void finalize(Uint8List trailer) => _cl._sealedOpenerFinalize(_h, trailer);
  void close() { if (_h != nullptr) { _cl._sealedOpenerFree(_h); _h = nullptr; } }
}

/// Sealed-messaging methods on CryptoLib (tier 0=Flagship, 1=Fortress).
extension CryptoLibSealed on CryptoLib {
  /// Generate a party's recipient (KEM) + sender (signature) keypairs.
  Identity newIdentity(SealedTier tier) {
    final r = _extractKeyPair(_lib.lookupFunction<CryptoKeyPair Function(Int32),
        CryptoKeyPair Function(int)>('cryptolib_sealed_generate_recipient')(tier.index));
    final s = _extractKeyPair(_lib.lookupFunction<CryptoKeyPair Function(Int32),
        CryptoKeyPair Function(int)>('cryptolib_sealed_generate_sender')(tier.index));
    return Identity(this, tier, r.publicKey, r.secretKey, s.publicKey, s.secretKey);
  }

  /// Read an envelope's public header without any key. Null if unrecognizable.
  SealedInfo? sealedInspect(Uint8List envelope) {
    final pe = _toNative(envelope);
    try {
      final info = _lib.lookupFunction<CryptoSealedInfo Function(Pointer<Uint8>, Size),
          CryptoSealedInfo Function(Pointer<Uint8>, int)>('cryptolib_sealed_inspect')(pe, envelope.length);
      if (info.ok == 0) return null;
      final fp = Uint8List(16);
      for (var i = 0; i < 16; i++) { fp[i] = info.fingerprint[i]; }
      return SealedInfo(
          version: info.version, suite: info.suite, streaming: info.streaming == 1,
          fingerprint: fp, kemCiphertextLen: info.kemCiphertextLen);
    } finally {
      if (pe != nullptr) calloc.free(pe);
    }
  }

  /// Whether the envelope is addressed to recipientPublic (fingerprint match).
  bool sealedAddressedTo(Uint8List envelope, Uint8List recipientPublic) {
    final pe = _toNative(envelope), pr = _toNative(recipientPublic);
    try {
      return _lib.lookupFunction<Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
              int Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_sealed_addressed_to')(
          pe, envelope.length, pr, recipientPublic.length) == 1;
    } finally {
      if (pe != nullptr) calloc.free(pe);
      if (pr != nullptr) calloc.free(pr);
    }
  }

  Uint8List sealedSeal(SealedTier tier, Uint8List pt, Uint8List recipientPublic,
      Uint8List senderSecret, {Uint8List? aad, Uint8List? purpose}) {
    final pp = _toNative(pt), pr = _toNative(recipientPublic), ps = _toNative(senderSecret);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    final pu = (purpose != null && purpose.isNotEmpty) ? _toNative(purpose) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_sealed_seal')(
          tier.index, pp, pt.length, pr, recipientPublic.length, ps, senderSecret.length,
          pa, aad?.length ?? 0, pu, purpose?.length ?? 0));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pr != nullptr) calloc.free(pr);
      if (ps != nullptr) calloc.free(ps);
      if (pa != nullptr) calloc.free(pa);
      if (pu != nullptr) calloc.free(pu);
    }
  }

  Uint8List sealedOpen(SealedTier tier, Uint8List envelope, Uint8List recipientSecret,
      Uint8List recipientPublic, Uint8List senderPublic, {Uint8List? aad, Uint8List? purpose}) {
    final pe = _toNative(envelope), prs = _toNative(recipientSecret),
        prp = _toNative(recipientPublic), psp = _toNative(senderPublic);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    final pu = (purpose != null && purpose.isNotEmpty) ? _toNative(purpose) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_sealed_open')(
          tier.index, pe, envelope.length, prs, recipientSecret.length, prp, recipientPublic.length,
          psp, senderPublic.length, pa, aad?.length ?? 0, pu, purpose?.length ?? 0));
    } finally {
      if (pe != nullptr) calloc.free(pe);
      if (prs != nullptr) calloc.free(prs);
      if (prp != nullptr) calloc.free(prp);
      if (psp != nullptr) calloc.free(psp);
      if (pa != nullptr) calloc.free(pa);
      if (pu != nullptr) calloc.free(pu);
    }
  }

  SealedStreamSealer sealedSealerBegin(SealedTier tier, Uint8List recipientPublic,
      Uint8List senderSecret, {Uint8List? purpose}) {
    final pr = _toNative(recipientPublic), ps = _toNative(senderSecret);
    final pu = (purpose != null && purpose.isNotEmpty) ? _toNative(purpose) : nullptr;
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>('cryptolib_sealed_sealer_begin')(
          tier.index, pr, recipientPublic.length, ps, senderSecret.length, pu, purpose?.length ?? 0, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: stream sealer begin failed');
      return SealedStreamSealer(this, h);
    } finally {
      if (pr != nullptr) calloc.free(pr);
      if (ps != nullptr) calloc.free(ps);
      if (pu != nullptr) calloc.free(pu);
      calloc.free(errPtr);
    }
  }

  Uint8List _sealedSealerPreamble(Pointer<Void> h) => _checkBufResult(_lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>), CryptoBufferResult Function(Pointer<Void>)>('cryptolib_sealed_sealer_preamble')(h));

  Uint8List _sealedSealerPush(Pointer<Void> h, Uint8List chunk) {
    final pc = _toNative(chunk);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)>('cryptolib_sealed_sealer_push')(h, pc, chunk.length));
    } finally { if (pc != nullptr) calloc.free(pc); }
  }

  (Uint8List, Uint8List) _sealedSealerFinalize(Pointer<Void> h, Uint8List? last) {
    final pl = (last != null && last.isNotEmpty) ? _toNative(last) : nullptr;
    final outTrailer = calloc<CryptoBuffer>();
    try {
      final ct = _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<CryptoBuffer>),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<CryptoBuffer>)>('cryptolib_sealed_sealer_finalize')(
          h, pl, last?.length ?? 0, outTrailer));
      return (ct, _copyBuf(outTrailer.ref));
    } finally { if (pl != nullptr) calloc.free(pl); calloc.free(outTrailer); }
  }

  void _sealedSealerFree(Pointer<Void> h) => _lib.lookupFunction<
      Void Function(Pointer<Void>), void Function(Pointer<Void>)>('cryptolib_sealed_sealer_free')(h);

  SealedStreamOpener sealedOpenerBegin(SealedTier tier, Uint8List preamble,
      Uint8List recipientSecret, Uint8List recipientPublic, Uint8List senderPublic, {Uint8List? purpose}) {
    final pp = _toNative(preamble), prs = _toNative(recipientSecret),
        prp = _toNative(recipientPublic), psp = _toNative(senderPublic);
    final pu = (purpose != null && purpose.isNotEmpty) ? _toNative(purpose) : nullptr;
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>('cryptolib_sealed_opener_begin')(
          tier.index, pp, preamble.length, prs, recipientSecret.length, prp, recipientPublic.length,
          psp, senderPublic.length, pu, purpose?.length ?? 0, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: stream opener begin failed');
      return SealedStreamOpener(this, h);
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (prs != nullptr) calloc.free(prs);
      if (prp != nullptr) calloc.free(prp);
      if (psp != nullptr) calloc.free(psp);
      if (pu != nullptr) calloc.free(pu);
      calloc.free(errPtr);
    }
  }

  (Uint8List, bool) _sealedOpenerPull(Pointer<Void> h, Uint8List ct) {
    final pc = _toNative(ct);
    final outFinal = calloc<Int32>();
    try {
      final pt = _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<Int32>),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<Int32>)>('cryptolib_sealed_opener_pull')(h, pc, ct.length, outFinal));
      return (pt, outFinal.value == 1);
    } finally { if (pc != nullptr) calloc.free(pc); calloc.free(outFinal); }
  }

  void _sealedOpenerFinalize(Pointer<Void> h, Uint8List trailer) {
    final pt = _toNative(trailer);
    try {
      _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)>('cryptolib_sealed_opener_finalize')(h, pt, trailer.length));
    } finally { if (pt != nullptr) calloc.free(pt); }
  }

  void _sealedOpenerFree(Pointer<Void> h) => _lib.lookupFunction<
      Void Function(Pointer<Void>), void Function(Pointer<Void>)>('cryptolib_sealed_opener_free')(h);
}
