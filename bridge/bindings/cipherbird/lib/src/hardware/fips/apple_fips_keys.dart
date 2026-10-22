import 'dart:ffi';
import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/apple_fips_call.dart';
import 'package:ffi/ffi.dart';

/// P-256 through CryptoKit: 65-byte public points, 32-byte scalars, DER
/// signatures.
final class AppleFipsKeys {
  const AppleFipsKeys._();

  static KeyPairResult keygen() {
    final pubOut = calloc<Pointer<Uint8>>(), pubLen = calloc<IntPtr>();
    try {
      final priv = AppleFipsCall.run(
        [],
        (b, _, o, l) => b.p256Keygen(pubOut, pubLen, o, l),
      );
      return KeyPairResult(
        publicKey: AppleFipsCall.take(pubOut, pubLen),
        secretKey: priv,
      );
    } finally {
      calloc.free(pubOut);
      calloc.free(pubLen);
    }
  }

  static Uint8List ecdh(Uint8List privateKey, Uint8List peerPublic) =>
      AppleFipsCall.run(
        [privateKey, peerPublic],
        (b, i, o, l) => b.p256Ecdh(
          i[0],
          privateKey.length,
          i[1],
          peerPublic.length,
          o,
          l,
        ),
      );

  static Uint8List sign(Uint8List privateKey, Uint8List message) =>
      AppleFipsCall.run(
        [privateKey, message],
        (b, i, o, l) => b.p256Sign(
          i[0],
          privateKey.length,
          i[1],
          message.length,
          o,
          l,
        ),
      );

  static bool verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) {
    final ins = [
      publicKey,
      message,
      signature,
    ].map(AppleFipsCall.toNative).toList();
    try {
      return AppleFipsCall.bindings.p256Verify(
            ins[0],
            publicKey.length,
            ins[1],
            message.length,
            ins[2],
            signature.length,
          ) ==
          1;
    } finally {
      AppleFipsCall.freeNative(ins[0], publicKey.length);
      AppleFipsCall.freeNative(ins[1], message.length);
      AppleFipsCall.freeNative(ins[2], signature.length);
    }
  }
}
