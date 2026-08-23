part of '../cryptolib.dart';

// ── Composed carriers: encryption whose ciphertext lives inside a media file ──
// Each of these seals a message AND hides the result in a cover carrier, so the
// output looks like an ordinary image/audio/video file. They differ in what the
// recipient must supply to open it.
//
// Steganography is defence-in-depth here, never the confidentiality boundary:
// the payload is authenticated-encrypted first, so security rests on the key,
// not on the carrier going unnoticed.

/// Composed seal/open operations on CryptoLib.
extension CryptoLibComposed on CryptoLib {
  // ── Forward error correction ───────────────────────────────────────────────

  /// FEC-encode [data] under [scheme]. Apply before embedding when the carrier
  /// may be degraded in transit.
  Uint8List fecEncode(Uint8List data, FecScheme scheme) {
    final d = _toNative(data);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Int32),
          CryptoBufferResult Function(Pointer<Uint8>, int, int)>('cryptolib_fec_encode')(
        d, data.length, scheme.value));
    } finally {
      if (d != nullptr) calloc.free(d);
    }
  }

  /// FEC-decode [data], recovering [originalLength] bytes. [scheme] and
  /// [originalLength] must match what [fecEncode] was given.
  Uint8List fecDecode(Uint8List data, FecScheme scheme, int originalLength) {
    final d = _toNative(data);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Int32, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, int, int)>('cryptolib_fec_decode')(
        d, data.length, scheme.value, originalLength));
    } finally {
      if (d != nullptr) calloc.free(d);
    }
  }

  // ── Physical seal — "the key is a file you hold" ───────────────────────────

  /// Seal [plaintext] under a key derived from [keyMediaPath], hiding the
  /// result inside [coverPath] and writing it to [outputPath].
  ///
  /// Opening needs BOTH files: the key media (which never leaves your hands)
  /// and the carrier. The key file is conditioned deterministically, so the
  /// same file always yields the same key and nothing needs to be stored.
  void physicalSeal({
    required String keyMediaPath,
    required Uint8List plaintext,
    required String coverPath,
    required String outputPath,
    Uint8List? aad,
  }) {
    final km = keyMediaPath.toNativeUtf8();
    final pt = _toNative(plaintext);
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final cv = coverPath.toNativeUtf8();
    final out = outputPath.toNativeUtf8();
    try {
      _checkResult(_lib.lookupFunction<
          CryptoResult Function(Pointer<Utf8>, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Utf8>, Pointer<Utf8>),
          CryptoResult Function(Pointer<Utf8>, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Utf8>, Pointer<Utf8>)>('cryptolib_physical_seal')(
        km, pt, plaintext.length, a, aad?.length ?? 0, cv, out));
    } finally {
      calloc.free(km);
      if (pt != nullptr) calloc.free(pt);
      if (a != nullptr) calloc.free(a);
      calloc.free(cv);
      calloc.free(out);
    }
  }

  /// Recover a [physicalSeal]ed message. Requires the same key media file and
  /// the same [aad].
  Uint8List physicalOpen({
    required String keyMediaPath,
    required String stegoPath,
    Uint8List? aad,
  }) {
    final km = keyMediaPath.toNativeUtf8();
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final sp = stegoPath.toNativeUtf8();
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, Size, Pointer<Utf8>),
          CryptoBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, int, Pointer<Utf8>)>('cryptolib_physical_open')(
        km, a, aad?.length ?? 0, sp));
    } finally {
      calloc.free(km);
      if (a != nullptr) calloc.free(a);
      calloc.free(sp);
    }
  }

  // ── Image factor — know (secret) AND have (exact image) ────────────────────

  /// Seal [plaintext] behind two factors: the OPRF secret [oprfSecretSeed]
  /// (something you know) and the exact [referenceImagePath] (something you
  /// have). The ciphertext is hidden in [coverPath] → [outputPath].
  ///
  /// Both factors are required to open; neither alone reveals anything.
  void imageFactorSeal({
    required Uint8List oprfSecretSeed,
    required String referenceImagePath,
    required Uint8List plaintext,
    required String coverPath,
    required String outputPath,
    Uint8List? aad,
  }) {
    final seed = _toNative(oprfSecretSeed);
    final ref = referenceImagePath.toNativeUtf8();
    final pt = _toNative(plaintext);
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final cv = coverPath.toNativeUtf8();
    final out = outputPath.toNativeUtf8();
    try {
      _checkResult(_lib.lookupFunction<
          CryptoResult Function(Pointer<Uint8>, Size, Pointer<Utf8>, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Utf8>, Pointer<Utf8>),
          CryptoResult Function(Pointer<Uint8>, int, Pointer<Utf8>, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Utf8>, Pointer<Utf8>)>('cryptolib_image_factor_seal')(
        seed, oprfSecretSeed.length, ref, pt, plaintext.length, a, aad?.length ?? 0, cv, out));
    } finally {
      if (seed != nullptr) calloc.free(seed);
      calloc.free(ref);
      if (pt != nullptr) calloc.free(pt);
      if (a != nullptr) calloc.free(a);
      calloc.free(cv);
      calloc.free(out);
    }
  }

  /// Recover an [imageFactorSeal]ed message. Needs the same secret seed, the
  /// same reference image, and the same [aad].
  Uint8List imageFactorOpen({
    required Uint8List oprfSecretSeed,
    required String referenceImagePath,
    required String stegoPath,
    Uint8List? aad,
  }) {
    final seed = _toNative(oprfSecretSeed);
    final ref = referenceImagePath.toNativeUtf8();
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final sp = stegoPath.toNativeUtf8();
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Utf8>, Pointer<Uint8>, Size, Pointer<Utf8>),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Utf8>, Pointer<Uint8>, int, Pointer<Utf8>)>('cryptolib_image_factor_open')(
        seed, oprfSecretSeed.length, ref, a, aad?.length ?? 0, sp));
    } finally {
      if (seed != nullptr) calloc.free(seed);
      calloc.free(ref);
      if (a != nullptr) calloc.free(a);
      calloc.free(sp);
    }
  }

  // ── HPKE stego — public-key sealing into a carrier ─────────────────────────

  /// Seal [plaintext] to the recipient's HPKE public key [recipientPublic] and
  /// hide it in [coverPath] → [outputPath].
  ///
  /// Returns the public KEM encapsulation (`enc`) — transmit it alongside the
  /// carrier, since the recipient needs it to open. Get keys from
  /// `hpkeKeygen()` / `hpkeDeriveKeyPair()`.
  Uint8List hpkeStegoSeal({
    required Uint8List recipientPublic,
    required Uint8List plaintext,
    required String coverPath,
    required String outputPath,
    Uint8List? aad,
    Uint8List? info,
  }) {
    final pk = _toNative(recipientPublic);
    final pt = _toNative(plaintext);
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final i = (info == null || info.isEmpty) ? nullptr : _toNative(info);
    final cv = coverPath.toNativeUtf8();
    final out = outputPath.toNativeUtf8();
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Utf8>, Pointer<Utf8>),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Utf8>, Pointer<Utf8>)>('cryptolib_hpke_stego_seal')(
        pk, recipientPublic.length, pt, plaintext.length, a, aad?.length ?? 0,
        i, info?.length ?? 0, cv, out));
    } finally {
      if (pk != nullptr) calloc.free(pk);
      if (pt != nullptr) calloc.free(pt);
      if (a != nullptr) calloc.free(a);
      if (i != nullptr) calloc.free(i);
      calloc.free(cv);
      calloc.free(out);
    }
  }

  /// Open an [hpkeStegoSeal]ed carrier with the recipient secret key and the
  /// `enc` value returned by the sealer. [aad] and [info] must match.
  Uint8List hpkeStegoOpen({
    required Uint8List recipientSecret,
    required Uint8List enc,
    required String stegoPath,
    Uint8List? aad,
    Uint8List? info,
  }) {
    final sk = _toNative(recipientSecret);
    final e = _toNative(enc);
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final i = (info == null || info.isEmpty) ? nullptr : _toNative(info);
    final sp = stegoPath.toNativeUtf8();
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Utf8>),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Utf8>)>('cryptolib_hpke_stego_open')(
        sk, recipientSecret.length, e, enc.length, a, aad?.length ?? 0,
        i, info?.length ?? 0, sp));
    } finally {
      if (sk != nullptr) calloc.free(sk);
      if (e != nullptr) calloc.free(e);
      if (a != nullptr) calloc.free(a);
      if (i != nullptr) calloc.free(i);
      calloc.free(sp);
    }
  }
}
