import 'dart:isolate';
import 'dart:typed_data';

import 'package:cipherbird/src/hardware/apple_call.dart';
import 'package:cipherbird/src/hardware/hardware_attestation.dart';
import 'package:cipherbird/src/hardware/hardware_backend.dart';
import 'package:cipherbird/src/hardware/hardware_backing.dart';
import 'package:cipherbird/src/hardware/hardware_key_exception.dart';
import 'package:ffi/ffi.dart';

/// Secure Enclave through the plugin's Swift functions; unwrap and attest
/// run on a helper isolate so the UI isolate never waits behind a prompt.
final class AppleBackend implements HardwareBackend {
  const AppleBackend();
  @override
  Future<HardwareBacking> create(
    String label, {
    required bool biometric,
  }) async {
    final status = AppleCall.withLabel(
      label,
      (b, l) => b.create(l, biometric ? 1 : 0),
    );
    AppleCall.check(status);
    return backing(label);
  }

  @override
  Future<bool> exists(String label) async =>
      AppleCall.withLabel(label, (b, l) => b.exists(l)) == 1;

  @override
  Future<void> delete(String label) async =>
      AppleCall.check(AppleCall.withLabel(label, (b, l) => b.delete(l)));

  @override
  Future<HardwareBacking> backing(String label) async =>
      switch (AppleCall.withLabel(label, (b, l) => b.backing(l))) {
        1 => HardwareBacking.secureEnclave,
        2 => HardwareBacking.software,
        _ => HardwareBacking.none,
      };

  @override
  Future<Uint8List> wrap(String label, Uint8List input) async =>
      AppleCall.withOutput(label, (b, l, out, len) {
        final pin = AppleCall.toNative(input);
        try {
          return b.wrap(l, pin, input.length, out, len);
        } finally {
          AppleCall.freeNative(pin, input.length);
        }
      });

  @override
  Future<Uint8List> unwrap(
    String label,
    Uint8List blob, {
    required String reason,
  }) => Isolate.run(
    () => AppleCall.withOutput(label, (b, l, out, len) {
      final pin = AppleCall.toNative(blob);
      final preason = reason.toNativeUtf8();
      try {
        return b.unwrap(l, pin, blob.length, preason, out, len);
      } finally {
        AppleCall.freeNative(pin, blob.length);
        malloc.free(preason);
      }
    }),
  );

  @override
  Future<HardwareAttestation> attest(String label, Uint8List challenge) async {
    final payload = await Isolate.run(
      () => AppleCall.withOutput(label, (b, l, out, len) {
        final pin = AppleCall.toNative(challenge);
        try {
          return b.attest(l, pin, challenge.length, out, len);
        } finally {
          AppleCall.freeNative(pin, challenge.length);
        }
      }),
    );
    final split = payload.indexOf(0);
    if (split <= 0) {
      throw const HardwareKeyException('failed', 'malformed attestation');
    }
    final publicKey = AppleCall.withOutput(
      label,
      (b, l, out, len) => b.publicKey(l, out, len),
    );
    return HardwareAttestation(
      kind: AttestationKind.appAttest,
      keyId: String.fromCharCodes(payload.sublist(0, split)),
      document: Uint8List.sublistView(payload, split + 1),
      publicKey: publicKey,
    );
  }
}
