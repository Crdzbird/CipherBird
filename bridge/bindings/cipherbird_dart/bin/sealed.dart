// CipherBird for Dart — Flagship / Fortress: state-of-the-art sealed messaging.
//
// Two assurance tiers of one construction: encapsulate → sign-then-encrypt inside
// a key-committing cascade, recipient-bound, auth-first.
//   CRYPTOLIB_DYLIB=../../build/release/libcipherbird.dylib dart run bin/sealed.dart
import 'dart:io';
import 'dart:typed_data';
import 'package:cipherbird_dart/cipherbird_dart.dart';

int pass = 0, fail = 0;
void ck(String n, bool ok) {
  print('   ${ok ? '✓' : '✗'} $n');
  ok ? pass++ : fail++;
}

Uint8List b(String s) => Uint8List.fromList(s.codeUnits);

void demo(CipherBird lib, SealedTier tier, String name, String blurb) {
  print('\n── $name ──  $blurb');

  // Each party is an Identity: recipient (KEM) keypair to RECEIVE, sender
  // (signature) keypair to SIGN. Publish the publics, keep the secrets.
  final alice = lib.newIdentity(tier);
  final bob = lib.newIdentity(tier);
  final aad = b('thread-42'), purpose = b('secure-note');

  // One-shot: Bob seals TO Alice, signed by Bob.
  final env = bob.seal(
    b('the eagle lands at dawn'),
    alice.recipientPublic,
    aad: aad,
    purpose: purpose,
  );
  final pt = alice.open(env, bob.senderPublic, aad: aad, purpose: purpose);
  ck(
    'one-shot seal → open round-trips',
    String.fromCharCodes(pt) == 'the eagle lands at dawn',
  );

  // Auth-first: a forged sender is rejected.
  final mallory = lib.newIdentity(tier);
  var forged = false;
  try {
    alice.open(env, mallory.senderPublic, aad: aad, purpose: purpose);
  } catch (_) {
    forged = true;
  }
  ck('forged sender rejected (auth-first)', forged);

  // Inspect + address without any key.
  final info = lib.sealedInspect(env)!;
  ck(
    'inspect: suite=${info.suite} streaming=${info.streaming} ct=${info.kemCiphertextLen}B',
    info.suite.suiteId == (name == 'Fortress' ? 2 : 1) && !info.streaming,
  );
  ck(
    'addressed to Alice, not Mallory',
    lib.sealedAddressedTo(env, alice.recipientPublic) &&
        !lib.sealedAddressedTo(env, mallory.recipientPublic),
  );

  // Streaming: preamble → chunks → signed trailer.
  final sealer = bob.newStreamSealer(alice.recipientPublic, purpose: purpose);
  final preamble = sealer.preamble();
  final parts = ['chunk-one ', 'chunk-two ', 'chunk-three'];
  final wire = <Uint8List>[];
  for (final p in parts.sublist(0, parts.length - 1)) {
    wire.add(sealer.push(b(p)));
  }
  final (lastCt, trailer) = sealer.finalize(b(parts.last));
  sealer.close();

  final opener = alice.newStreamOpener(
    preamble,
    bob.senderPublic,
    purpose: purpose,
  );
  final assembled = BytesBuilder();
  var sawFinal = false;
  for (final ct in wire) {
    final (p, _) = opener.pull(ct);
    assembled.add(p);
  }
  final (p, isFinal) = opener.pull(lastCt);
  assembled.add(p);
  sawFinal = isFinal;
  opener.finalize(
    trailer,
  ); // verifies whole-stream signature (throws on tamper)
  opener.close();
  ck(
    'streaming round-trips + trailer verifies',
    String.fromCharCodes(assembled.toBytes()) == parts.join() && sawFinal,
  );
}

void main() {
  final lib = CipherBird.load(Platform.environment['CRYPTOLIB_DYLIB']);
  lib.init();
  print('CipherBird ${lib.version()} — Flagship / Fortress (Dart)');
  demo(
    lib,
    SealedTier.flagship,
    'Flagship',
    'X25519+sntrup761 KEM · Ed25519+ML-DSA-65 sig',
  );
  demo(
    lib,
    SealedTier.fortress,
    'Fortress',
    'triple KEM (+ML-KEM-768) · triple sig (+SLH-DSA)',
  );
  print('\n$pass passed, $fail failed — sealed ${fail == 0 ? 'OK' : 'FAILED'}');
  exit(fail == 0 ? 0 : 1);
}
