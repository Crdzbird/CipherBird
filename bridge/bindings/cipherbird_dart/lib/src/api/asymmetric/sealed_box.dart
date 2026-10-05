part of '../../cryptolib.dart';

/// Asymmetric operations.
extension CryptoLibSealedBox on CryptoLib {
  /// SealedBox decrypt.
  Uint8List sealedboxDecrypt(
    Uint8List ciphertext,
    Uint8List recipientPub,
    Uint8List recipientSec,
  ) {
    final pc = _toNative(ciphertext);
    final prp = _toNative(recipientPub);
    final prs = _toNative(recipientSec);
    try {
      return _checkBufResult(
        _asymmetric.sealedboxDecrypt(
          pc,
          ciphertext.length,
          prp,
          recipientPub.length,
          prs,
          recipientSec.length,
        ),
      );
    } finally {
      if (pc != nullptr) {
        calloc.free(pc);
      }
      if (prp != nullptr) {
        calloc.free(prp);
      }
      if (prs != nullptr) {
        calloc.free(prs);
      }
    }
  }

  /// SealedBox encrypt (anonymous sender).
  Uint8List sealedboxEncrypt(Uint8List plaintext, Uint8List recipientPub) {
    final pp = _toNative(plaintext);
    final prp = _toNative(recipientPub);
    try {
      return _checkBufResult(
        _asymmetric.sealedboxEncrypt(
          pp,
          plaintext.length,
          prp,
          recipientPub.length,
        ),
      );
    } finally {
      if (pp != nullptr) {
        calloc.free(pp);
      }
      if (prp != nullptr) {
        calloc.free(prp);
      }
    }
  }
}
