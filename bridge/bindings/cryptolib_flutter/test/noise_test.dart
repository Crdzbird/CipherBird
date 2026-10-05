// Incremental BLAKE3 + Noise XX through the C ABI.
import 'dart:typed_data';
import 'package:cryptolib_flutter/cryptolib_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List b(String s) => Uint8List.fromList(s.codeUnits);

void main() {
  final lib = CryptoLib.instance;

  test('Noise XX: handshake, mutual auth, transport, fail-closed', () {
    final iks = lib.x25519Keygen(), rks = lib.x25519Keygen();
    final ini = lib.noise(
      initiator: true,
      staticPublic: iks.publicKey,
      staticSecret: iks.secretKey,
      prologue: b('pro'),
    );
    final res = lib.noise(
      initiator: false,
      staticPublic: rks.publicKey,
      staticSecret: rks.secretKey,
      prologue: b('pro'),
    );
    addTearDown(() {
      ini.close();
      res.close();
    });

    expect(res.readMessage(ini.writeMessage(b('hello'))), b('hello'));
    ini.readMessage(res.writeMessage());
    res.readMessage(ini.writeMessage());
    expect(ini.handshakeFinished && res.handshakeFinished, isTrue);
    expect(
      ini.remoteStatic,
      rks.publicKey,
      reason: 'initiator learns responder static',
    );
    expect(
      res.remoteStatic,
      iks.publicKey,
      reason: 'responder learns initiator static',
    );
    expect(ini.handshakeHash.length, 32);
    expect(ini.handshakeHash, res.handshakeHash);
    ini.split();
    res.split();
    expect(ini.split, throwsA(anything), reason: 'second split refused');

    final ct = ini.encrypt(b('first record'), b('ad'));
    expect(res.decrypt(ct, b('ad')), b('first record'));
    expect(ini.decrypt(res.encrypt(b('reply'))), b('reply'));
    final bad = Uint8List.fromList(ct)..[0] ^= 1;
    expect(() => res.decrypt(bad, b('ad')), throwsA(anything));
    expect(
      () => lib
          .noise(
            initiator: true,
            staticPublic: iks.publicKey,
            staticSecret: iks.secretKey,
          )
          .encrypt(b('x')),
      throwsA(anything),
      reason: 'encrypt before split',
    );
  });

  test(
    'decryptAt is order-independent and leaves the session counter alone',
    () {
      final iks = lib.x25519Keygen(), rks = lib.x25519Keygen();
      final ini = lib.noise(
        initiator: true,
        staticPublic: iks.publicKey,
        staticSecret: iks.secretKey,
      );
      final res = lib.noise(
        initiator: false,
        staticPublic: rks.publicKey,
        staticSecret: rks.secretKey,
      );
      addTearDown(() {
        ini.close();
        res.close();
      });
      res.readMessage(ini.writeMessage());
      ini.readMessage(res.writeMessage());
      res.readMessage(ini.writeMessage());
      ini.split();
      res.split();

      // Fresh session: sender counters start at 0, so recs[i] is at counter i.
      final texts = ['r0', 'record one', 'r2', 'r3'];
      final recs = [for (final t in texts) ini.encrypt(b(t))];
      for (var i = recs.length - 1; i >= 0; i--) {
        expect(
          res.decryptAt(i, recs[i]),
          b(texts[i]),
          reason: 'out-of-order open of $i',
        );
      }
      expect(
        res.decrypt(recs[0]),
        b('r0'),
        reason: 'sequential path untouched',
      );
      expect(
        () => res.decryptAt(1, recs[0]),
        throwsA(anything),
        reason: 'tag binds the counter',
      );
      expect(
        () => res.decryptAt(-1, recs[0]),
        throwsA(anything),
        reason: 'reserved 2^64-1',
      );
    },
  );

  test('incremental BLAKE3 matches one-shot; keyed and XOF modes', () {
    final msg = b('incremental hashing across several chunks of input');
    final want = lib.blake3(msg);
    final h = lib.blake3Hasher();
    addTearDown(h.close);
    h.update(msg.sublist(0, 7));
    h.update(msg.sublist(7, 20));
    h.update(msg.sublist(20));
    expect(h.finalize(), want);
    expect(
      () => h.update(b('late')),
      throwsA(anything),
      reason: 'update after finalize',
    );

    final kh = lib.blake3Hasher(key: Uint8List(32))..update(msg);
    addTearDown(kh.close);
    expect(kh.finalize(), isNot(want));
    expect(() => lib.blake3Hasher(key: Uint8List(31)), throwsArgumentError);

    final xh = lib.blake3Hasher()..update(msg);
    addTearDown(xh.close);
    final xof = xh.finalize(outLen: 64);
    expect(xof.length, 64);
    expect(xof.sublist(0, 32), want);
    h.close();
    h.close(); // idempotent
  });
}
