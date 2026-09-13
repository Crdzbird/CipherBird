// Incremental BLAKE3 + Noise XX through dart:ffi.
//   dart run bin/noise_verify.dart [path-to-libcryptolib_c.dylib]
import 'dart:io';
import 'dart:typed_data';
import 'package:cryptolib_dart/cryptolib_ffi.dart';

int _f = 0;
void check(bool ok, String l) { stdout.writeln('${ok ? "  ok  " : " FAIL "} $l'); if (!ok) _f++; }
bool throws(void Function() f) { try { f(); return false; } catch (_) { return true; } }
bool eq(Uint8List a, Uint8List b) { if (a.length != b.length) return false; for (var i = 0; i < a.length; i++) { if (a[i] != b[i]) return false; } return true; }
Uint8List b(String s) => Uint8List.fromList(s.codeUnits);

void main(List<String> args) {
  final lib = CryptoLib.load(args.isNotEmpty ? args[0] : 'build/release/libcryptolib_c.dylib');
  lib.init();

  final iks = lib.x25519Keygen(), rks = lib.x25519Keygen();
  final ini = lib.noise(initiator: true, staticPublic: iks.publicKey, staticSecret: iks.secretKey, prologue: b('pro'));
  final res = lib.noise(initiator: false, staticPublic: rks.publicKey, staticSecret: rks.secretKey, prologue: b('pro'));
  check(eq(res.readMessage(ini.writeMessage(b('hello'))), b('hello')), 'handshake payload delivered');
  ini.readMessage(res.writeMessage());
  res.readMessage(ini.writeMessage());
  check(ini.handshakeFinished && res.handshakeFinished, 'handshake finished both sides');
  check(eq(ini.remoteStatic, rks.publicKey) && eq(res.remoteStatic, iks.publicKey), 'mutual static authentication');
  check(ini.handshakeHash.length == 32 && eq(ini.handshakeHash, res.handshakeHash), 'handshake hash agrees (32 B)');
  ini.split(); res.split();
  check(throws(ini.split), 'second split refused');

  final ct = ini.encrypt(b('first record'), b('ad'));
  check(eq(res.decrypt(ct, b('ad')), b('first record')), 'transport round-trip');
  check(eq(ini.decrypt(res.encrypt(b('reply'))), b('reply')), 'reverse direction');
  final bad = Uint8List.fromList(ct); bad[0] ^= 1;
  check(throws(() => res.decrypt(bad, b('ad'))), 'tampered record rejected');

  // 'first record' already consumed sender counter 0, so recs[i] was sealed at
  // counter i + base — the caller must supply the counter the SENDER used.
  const base = 1;
  final texts = ['r0', 'record one', 'r2', 'r3'];
  final recs = [for (final t in texts) ini.encrypt(b(t))];
  var ooo = true;
  for (var i = recs.length - 1; i >= 0; i--) { ooo = ooo && eq(res.decryptAt(base + i, recs[i]), b(texts[i])); }
  check(ooo, 'decryptAt opens records out of order');
  check(eq(res.decrypt(recs[0]), b('r0')), 'sequential counter untouched');
  check(throws(() => res.decryptAt(0, recs[0])), 'wrong counter rejected');
  check(throws(() => res.decryptAt(-1, recs[0])), 'reserved nonce (2^64-1) rejected');
  check(throws(() => lib.noise(initiator: true, staticPublic: iks.publicKey, staticSecret: iks.secretKey).encrypt(b('x'))),
      'encrypt before split fails');
  ini.close(); res.close(); res.close();

  final msg = b('incremental hashing across several chunks of input');
  final want = lib.blake3(msg);
  final h = lib.blake3Hasher();
  h.update(msg.sublist(0, 7)); h.update(msg.sublist(7, 20)); h.update(msg.sublist(20));
  check(eq(h.finalize(), want), 'incremental == one-shot blake3');
  check(throws(() => h.update(b('late'))), 'update after finalize fails');
  final kh = lib.blake3Hasher(key: Uint8List(32)); kh.update(msg);
  check(!eq(kh.finalize(), want), 'keyed digest differs');
  check(throws(() => lib.blake3Hasher(key: Uint8List(31))), '31-byte key refused');
  final xh = lib.blake3Hasher(); xh.update(msg);
  final xof = xh.finalize(outLen: 64);
  check(xof.length == 64 && eq(xof.sublist(0, 32), want), 'XOF prefix equals 32-byte digest');
  h.close(); kh.close(); xh.close();

  stdout.writeln(_f == 0 ? '\nALL PASS' : '\n$_f FAILURE(S)');
  exit(_f == 0 ? 0 : 1);
}
