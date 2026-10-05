part of '../../cryptolib.dart';

/// Asymmetric operations.
extension CryptoLibBox on CryptoLib {
  /// Box encrypt: sender to recipient authenticated encryption.
  Uint8List boxEncrypt(
    Uint8List plaintext,
    Uint8List recipientPub,
    Uint8List senderSec,
  ) {
    final pp = _toNative(plaintext);
    final prp = _toNative(recipientPub);
    final pss = _toNative(senderSec);
    try {
      return _checkBufResult(
        _asymmetric.boxEncrypt(
          pp,
          plaintext.length,
          prp,
          recipientPub.length,
          pss,
          senderSec.length,
        ),
      );
    } finally {
      if (pp != nullptr) {
        calloc.free(pp);
      }
      if (prp != nullptr) {
        calloc.free(prp);
      }
      if (pss != nullptr) {
        calloc.free(pss);
      }
    }
  }

  /// Box decrypt.
  Uint8List boxDecrypt(
    Uint8List ciphertext,
    Uint8List senderPub,
    Uint8List recipientSec,
  ) {
    final pc = _toNative(ciphertext);
    final psp = _toNative(senderPub);
    final prs = _toNative(recipientSec);
    try {
      return _checkBufResult(
        _asymmetric.boxDecrypt(
          pc,
          ciphertext.length,
          psp,
          senderPub.length,
          prs,
          recipientSec.length,
        ),
      );
    } finally {
      if (pc != nullptr) {
        calloc.free(pc);
      }
      if (psp != nullptr) {
        calloc.free(psp);
      }
      if (prs != nullptr) {
        calloc.free(prs);
      }
    }
  }
}
