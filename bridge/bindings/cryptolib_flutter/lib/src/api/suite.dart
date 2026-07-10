part of '../cryptolib.dart';

/// Suite — one-call advanced combinations.
///
/// A high-level facade that composes hybrid KEM, hybrid signatures,
/// MolecularVault, media entropy, keyring, Shamir and Keccak into single calls.
/// Every seal is authenticated and fails closed; the post-quantum envelopes are
/// self-describing (they carry the KEM ciphertext), so a recipient needs only
/// their long-term secret key. Requires the native library built with OpenSSL
/// and post-quantum support.
extension CryptoLibSuite on CryptoLib {
  /// Post-quantum message: encapsulate to [recipientKemPublic] and seal under
  /// the shared secret. Secure while EITHER X25519 or ML-KEM-768 holds.
  Uint8List suiteSealPq(Uint8List plaintext, Uint8List recipientKemPublic,
          {Uint8List? aad}) =>
      _suiteBuf('cryptolib_suite_seal_pq', plaintext, recipientKemPublic, aad);

  /// Open a [suiteSealPq] envelope with the recipient's hybrid-KEM secret key.
  Uint8List suiteOpenPq(Uint8List envelope, Uint8List recipientKemSecret,
          {Uint8List? aad}) =>
      _suiteBuf('cryptolib_suite_open_pq', envelope, recipientKemSecret, aad);

  /// Flagship: post-quantum confidentiality (hybrid KEM) + post-quantum
  /// authenticity (Ed25519+ML-DSA-65). [suiteOpenSignedPq] returns plaintext
  /// only if the signature verifies.
  Uint8List suiteSealSignedPq(Uint8List plaintext, Uint8List recipientKemPublic,
          Uint8List signerSigSecret, {Uint8List? aad}) =>
      _suiteBuf3('cryptolib_suite_seal_signed_pq', plaintext, recipientKemPublic,
          signerSigSecret, aad);

  /// Decrypt then verify; a signature mismatch throws and yields no plaintext.
  Uint8List suiteOpenSignedPq(Uint8List envelope, Uint8List recipientKemSecret,
          Uint8List signerSigPublic, {Uint8List? aad}) =>
      _suiteBuf3('cryptolib_suite_open_signed_pq', envelope, recipientKemSecret,
          signerSigPublic, aad);

  /// File-as-key: deterministic media entropy from [path] derives the master.
  Uint8List suiteSealWithFile(Uint8List plaintext, String path, {Uint8List? aad}) =>
      _suiteFile('cryptolib_suite_seal_with_file', plaintext, path, aad);

  /// Re-derive from the same file and open the envelope.
  Uint8List suiteOpenWithFile(Uint8List envelope, String path, {Uint8List? aad}) =>
      _suiteFile('cryptolib_suite_open_with_file', envelope, path, aad);

  /// Keyring-guarded: a device-factor unlock provides the MolecularVault master.
  Uint8List suiteSealWithKeyringDevice(Uint8List plaintext, Pointer<Void> keyring,
          Uint8List factorKey, {Uint8List? aad}) =>
      _suiteKeyringFactor('cryptolib_suite_seal_with_keyring_device', plaintext,
          keyring, factorKey, aad);

  Uint8List suiteOpenWithKeyringDevice(Uint8List envelope, Pointer<Void> keyring,
          Uint8List factorKey, {Uint8List? aad}) =>
      _suiteKeyringFactor('cryptolib_suite_open_with_keyring_device', envelope,
          keyring, factorKey, aad);

  /// Keyring-guarded via a passphrase slot.
  Uint8List suiteSealWithKeyringPassphrase(Uint8List plaintext,
          Pointer<Void> keyring, String passphrase, {Uint8List? aad}) =>
      _suiteKeyringPass('cryptolib_suite_seal_with_keyring_passphrase', plaintext,
          keyring, passphrase, aad);

  Uint8List suiteOpenWithKeyringPassphrase(Uint8List envelope,
          Pointer<Void> keyring, String passphrase, {Uint8List? aad}) =>
      _suiteKeyringPass('cryptolib_suite_open_with_keyring_passphrase', envelope,
          keyring, passphrase, aad);

  /// EVM address (20 bytes) from a 65-byte uncompressed secp256k1 public key.
  Uint8List suiteEvmAddress(Uint8List secp256k1PublicKey) {
    final pk = _toNative(secp256k1PublicKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int)>(
          'cryptolib_suite_evm_address')(pk, secp256k1PublicKey.length));
    } finally {
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// Threshold (k-of-n): seal under a fresh master, split it into [n] Shamir
  /// shares of which any [k] reconstruct it. Returns the envelope and the [n]
  /// individual share records; distribute the shares, keep the envelope
  /// anywhere. Open with [suiteOpenThreshold] using any `k` of the shares.
  (Uint8List envelope, List<Uint8List> shares) suiteSealThreshold(
      Uint8List plaintext, int n, int k, {Uint8List? aad}) {
    final pp = _toNative(plaintext);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    final outShares = calloc<CryptoBuffer>();
    try {
      final r = _lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Uint8, Uint8,
              Pointer<Uint8>, Size, Pointer<CryptoBuffer>),
          CryptoBufferResult Function(Pointer<Uint8>, int, int, int,
              Pointer<Uint8>, int, Pointer<CryptoBuffer>)>(
          'cryptolib_suite_seal_threshold')(
          pp, plaintext.length, n, k, pa, aad?.length ?? 0, outShares);
      final env = _checkBufResult(r); // throws on error (outShares stays empty)
      final blob = _copyBuf(outShares.ref);
      return (env, _splitShareRecords(blob));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pa != nullptr) calloc.free(pa);
      calloc.free(outShares);
    }
  }

  /// Reconstruct the master from any k of the shares and open the envelope.
  Uint8List suiteOpenThreshold(Uint8List envelope, List<Uint8List> shares,
      {Uint8List? aad}) {
    final blob = BytesBuilder();
    for (final s in shares) {
      blob.add(s);
    }
    final joined = blob.toBytes();
    final pe = _toNative(envelope);
    final ps = _toNative(joined);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int)>('cryptolib_suite_open_threshold')(
          pe, envelope.length, ps, joined.length, pa, aad?.length ?? 0));
    } finally {
      if (pe != nullptr) calloc.free(pe);
      if (ps != nullptr) calloc.free(ps);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  // ── shared plumbing ───────────────────────────────────────────────────────

  Uint8List _suiteBuf(String symbol, Uint8List a, Uint8List b, Uint8List? aad) {
    final pa = _toNative(a), pb = _toNative(b);
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int)>(symbol)(
          pa, a.length, pb, b.length, pad, aad?.length ?? 0));
    } finally {
      if (pa != nullptr) calloc.free(pa);
      if (pb != nullptr) calloc.free(pb);
      if (pad != nullptr) calloc.free(pad);
    }
  }

  Uint8List _suiteBuf3(String symbol, Uint8List a, Uint8List b, Uint8List c,
      Uint8List? aad) {
    final pa = _toNative(a), pb = _toNative(b), pc = _toNative(c);
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int)>(symbol)(
          pa, a.length, pb, b.length, pc, c.length, pad, aad?.length ?? 0));
    } finally {
      if (pa != nullptr) calloc.free(pa);
      if (pb != nullptr) calloc.free(pb);
      if (pc != nullptr) calloc.free(pc);
      if (pad != nullptr) calloc.free(pad);
    }
  }

  Uint8List _suiteFile(String symbol, Uint8List data, String path, Uint8List? aad) {
    final pd = _toNative(data);
    final cp = path.toNativeUtf8();
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Utf8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Utf8>,
              Pointer<Uint8>, int)>(symbol)(
          pd, data.length, cp, pad, aad?.length ?? 0));
    } finally {
      if (pd != nullptr) calloc.free(pd);
      calloc.free(cp);
      if (pad != nullptr) calloc.free(pad);
    }
  }

  Uint8List _suiteKeyringFactor(String symbol, Uint8List data,
      Pointer<Void> keyring, Uint8List factor, Uint8List? aad) {
    final pd = _toNative(data), pf = _toNative(factor);
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Void>,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Void>,
              Pointer<Uint8>, int, Pointer<Uint8>, int)>(symbol)(
          pd, data.length, keyring, pf, factor.length, pad, aad?.length ?? 0));
    } finally {
      if (pd != nullptr) calloc.free(pd);
      if (pf != nullptr) calloc.free(pf);
      if (pad != nullptr) calloc.free(pad);
    }
  }

  Uint8List _suiteKeyringPass(String symbol, Uint8List data,
      Pointer<Void> keyring, String passphrase, Uint8List? aad) {
    final pd = _toNative(data);
    final cpw = passphrase.toNativeUtf8();
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Void>,
              Pointer<Utf8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Void>,
              Pointer<Utf8>, Pointer<Uint8>, int)>(symbol)(
          pd, data.length, keyring, cpw, pad, aad?.length ?? 0));
    } finally {
      if (pd != nullptr) calloc.free(pd);
      calloc.free(cpw);
      if (pad != nullptr) calloc.free(pad);
    }
  }

  // Parse [index(1)|ylen(4 LE)|y] records into individual share byte-slices.
  List<Uint8List> _splitShareRecords(Uint8List blob) {
    final out = <Uint8List>[];
    var off = 0;
    while (off + 5 <= blob.length) {
      final yl = blob[off + 1] | (blob[off + 2] << 8) | (blob[off + 3] << 16) | (blob[off + 4] << 24);
      final end = off + 5 + yl;
      if (end > blob.length) break;
      out.add(Uint8List.sublistView(blob, off, end));
      off = end;
    }
    return out;
  }
}
