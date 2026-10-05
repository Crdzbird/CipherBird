part of '../../cryptolib.dart';

/// Suite - one-call advanced combinations.
///
/// A high-level facade that composes hybrid KEM, hybrid signatures,
/// MolecularVault, media entropy, keyring, Shamir and Keccak into single calls.
/// Every seal is authenticated and fails closed; the post-quantum envelopes are
/// self-describing (they carry the KEM ciphertext), so a recipient needs only
/// their long-term secret key. Requires the native library built with OpenSSL
/// and post-quantum support.
extension CryptoLibSuiteKeyringPassphraseCall on CryptoLib {
  Uint8List _suiteKeyringPass(
    String symbol,
    Uint8List data,
    Pointer<Void> keyring,
    String passphrase,
    Uint8List? aad,
  ) {
    final pd = _toNative(data);
    final cpw = passphrase.toNativeUtf8();
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Void>,
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Void>,
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
          )
        >(symbol)(pd, data.length, keyring, cpw, pad, aad?.length ?? 0),
      );
    } finally {
      if (pd != nullptr) {
        calloc.free(pd);
      }
      calloc.free(cpw);
      if (pad != nullptr) {
        calloc.free(pad);
      }
    }
  }

  List<Uint8List> _splitShareRecords(Uint8List blob) {
    final out = <Uint8List>[];
    var off = 0;
    while (off + 5 <= blob.length) {
      final yl =
          blob[off + 1] |
          (blob[off + 2] << 8) |
          (blob[off + 3] << 16) |
          (blob[off + 4] << 24);
      final end = off + 5 + yl;
      if (end > blob.length) {
        break;
      }
      out.add(Uint8List.sublistView(blob, off, end));
      off = end;
    }
    return out;
  }
}
