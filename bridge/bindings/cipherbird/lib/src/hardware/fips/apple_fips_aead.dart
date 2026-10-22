import 'dart:typed_data';

import 'package:cipherbird/src/hardware/fips/apple_fips_call.dart';

/// AES-256-GCM through CryptoKit; wires are nonce(12) | ciphertext | tag(16).
final class AppleFipsAead {
  const AppleFipsAead._();

  static final Uint8List _none = Uint8List(0);

  static Uint8List encrypt(Uint8List key, Uint8List plaintext, Uint8List? aad) {
    final a = aad ?? _none;
    return AppleFipsCall.run(
      [key, plaintext, a],
      (b, i, o, l) => b.aesGcmEncrypt(
        i[0],
        key.length,
        i[1],
        plaintext.length,
        i[2],
        a.length,
        o,
        l,
      ),
    );
  }

  static Uint8List decrypt(Uint8List key, Uint8List wire, Uint8List? aad) {
    final a = aad ?? _none;
    return AppleFipsCall.run(
      [key, wire, a],
      (b, i, o, l) => b.aesGcmDecrypt(
        i[0],
        key.length,
        i[1],
        wire.length,
        i[2],
        a.length,
        o,
        l,
      ),
    );
  }
}
