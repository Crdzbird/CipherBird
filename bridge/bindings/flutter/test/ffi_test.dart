// Runtime FFI test: loads the native library and exercises the real dart:ffi
// binding (lib/cryptolib_ffi.dart) the GUI app uses. `flutter test` runs this on
// the host VM, so it actually marshals data across the C boundary — not just a
// static analyze. Assumes `make lib` has built build/release/libcryptolib_c.dylib.
//
// This is the FULL showcase: every capability family the binding exposes —
// hashing, symmetric AEAD, asymmetric, vaults, post-quantum, BLS, and the
// multi-slot keyring — round-tripped across FFI.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:cryptolib_gui/cryptolib_ffi.dart';

String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
Uint8List _u(String s) => Uint8List.fromList(s.codeUnits);
bool _eq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void main() {
  final dylib = '../../../build/release/libcryptolib_c.dylib';

  test('native library is present', () {
    expect(File(dylib).existsSync(), isTrue,
        reason: 'run `make lib` first to build $dylib');
  });

  late CryptoLib lib;
  final abc = _u('abc');
  final msg = _u('secret payload');

  setUp(() {
    lib = CryptoLib.load(dylib);
    lib.init();
  });

  test('version', () => expect(lib.version(), '3.0.0'));

  test('hashing', () {
    expect(_hex(lib.sha256(abc)),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(lib.sha512(abc).length, 64);
    expect(lib.blake2b(abc).length, 64);
    final hk = lib.randomBytes(32);
    final mac = lib.hmacSha512(abc, hk);
    expect(lib.hmacSha512Verify(abc, mac, hk), isTrue);
    final phc =
        String.fromCharCodes(lib.argon2idHashStr('hunter2')).replaceAll('\x00', '');
    expect(lib.argon2idVerifyStr('hunter2', phc), isTrue);
  });

  test('symmetric AEAD', () {
    final sk = lib.randomBytes(32);
    final xct = lib.xchacha20Encrypt(msg, sk);
    expect(_eq(lib.xchacha20Decrypt(xct, sk), msg), isTrue);
    if (lib.aes256gcmAvailable()) {
      final act = lib.aes256gcmEncrypt(msg, sk);
      expect(_eq(lib.aes256gcmDecrypt(act, sk), msg), isTrue);
    }
  });

  test('asymmetric primitives', () {
    final ed = lib.ed25519Keygen();
    final sig = lib.ed25519Sign(abc, ed.secretKey);
    expect(lib.ed25519Verify(abc, sig, ed.publicKey), isTrue);

    final xa = lib.x25519Keygen(), xb = lib.x25519Keygen();
    expect(
        _eq(lib.x25519SharedSecret(xa.secretKey, xb.publicKey),
            lib.x25519SharedSecret(xb.secretKey, xa.publicKey)),
        isTrue);

    final r = lib.boxKeygen(), s = lib.boxKeygen();
    final bct = lib.boxEncrypt(msg, r.publicKey, s.secretKey);
    expect(_eq(lib.boxDecrypt(bct, s.publicKey, r.secretKey), msg), isTrue);

    final sct = lib.sealedboxEncrypt(msg, r.publicKey);
    expect(_eq(lib.sealedboxDecrypt(sct, r.publicKey, r.secretKey), msg), isTrue);
  });

  test('vaults', () {
    final vault = lib.vaultCreate(lib.randomBytes(32));
    final pkt = lib.vaultSeal(vault, msg, 'ctx');
    expect(_eq(lib.vaultOpen(vault, pkt, 'ctx'), msg), isTrue);
    lib.vaultFree(vault);

    final alice = lib.asymBundleGenerate(), bob = lib.asymBundleGenerate();
    final apkt = lib.asymVaultSeal(alice, bob.boxPublic, msg, 'ctx');
    expect(_eq(lib.asymVaultOpen(apkt, bob, alice.signPublic, 'ctx'), msg), isTrue);
  });

  test('post-quantum', () {
    final kem = lib.mlKemKeygen(1);
    final (kemCt, ssEnc) = lib.mlKemEncapsulate(kem.publicKey, 1);
    expect(_eq(ssEnc, lib.mlKemDecapsulate(kemCt, kem.secretKey, 1)), isTrue);

    final hkem = lib.hybridKemKeygen();
    final (hCt, hSsEnc) = lib.hybridKemEncapsulate(hkem.publicKey);
    expect(_eq(hSsEnc, lib.hybridKemDecapsulate(hCt, hkem.secretKey)), isTrue);
    expect(hSsEnc.length, 32);

    final dsa = lib.mlDsaKeygen(1);
    final dsig = lib.mlDsaSign(abc, dsa.secretKey, 1);
    expect(lib.mlDsaVerify(abc, dsig, dsa.publicKey, 1), isTrue);

    final slh = lib.slhDsaKeygen(1, 0);
    final ssig = lib.slhDsaSign(abc, slh.secretKey, 1, 0);
    expect(lib.slhDsaVerify(abc, ssig, slh.publicKey, 1, 0), isTrue);
  });

  test('BLS12-381', () {
    final bls = lib.blsKeygen();
    final bsig = lib.blsSign(abc, bls.secretKey);
    expect(lib.blsVerify(abc, bsig, bls.publicKey), isTrue);
  });

  test('keyring device == passphrase master', () {
    final factor = lib.randomBytes(32);
    final kr = lib.keyringCreate();
    lib.keyringAddDeviceSlot(kr, factor);
    lib.keyringAddPassphraseSlot(kr, 'cross-device pass', 0);
    expect(lib.keyringSlotCount(kr), 2);

    final blob = lib.keyringSerialise(kr);
    final kr2 = lib.keyringDeserialise(blob);
    final mDev = lib.keyringUnlockWithDevice(kr2, factor);
    final mPass = lib.keyringUnlockWithPassphrase(kr2, 'cross-device pass');
    expect(_eq(mDev, mPass), isTrue);
    expect(mDev.length, 32);

    lib.keyringFree(kr);
    lib.keyringFree(kr2);
  });

  // ── Phase 1-4 stego / FEC / analysis (synced from the standalone binding) ──
  late Directory tmp;
  String ppm(int seed, [int w = 256, int h = 256]) {
    tmp = Directory.systemTemp.createTempSync('cl_flutter_p4_');
    final p = '${tmp.path}/c_$seed.ppm';
    final body = Uint8List(w * h * 3);
    var s = seed == 0 ? 1 : seed;
    for (var i = 0; i < body.length; i++) {
      s ^= (s << 13) & 0xFFFFFFFF;
      s ^= s >> 17;
      s ^= (s << 5) & 0xFFFFFFFF;
      body[i] = s & 0xFF;
    }
    final f = File(p).openSync(mode: FileMode.write);
    f.writeFromSync('P6\n$w $h\n255\n'.codeUnits);
    f.writeFromSync(body);
    f.closeSync();
    return p;
  }

  test('keyed stego round-trip + wrong-key', () {
    final cover = ppm(0xC0FFEE);
    final out = '${tmp.path}/keyed.ppm';
    final key = Uint8List.fromList(List.filled(32, 0x5a));
    final payload = _u('keyed stego via Flutter');
    lib.stegoEmbedKeyed(cover, payload, out, key);
    expect(_eq(lib.stegoExtractKeyed(out, key), payload), isTrue);
    expect(() => lib.stegoExtractKeyed(out, Uint8List.fromList(List.filled(32, 0x99))),
        throwsException);
  });

  test('always-encrypt round-trip + wrong-key', () {
    final cover = ppm(0xBEEF);
    final out = '${tmp.path}/enc.ppm';
    final key = Uint8List.fromList(List.filled(32, 0x11));
    final secret = _u('never in the clear');
    lib.stegoEmbedEncrypted(cover, secret, out, key);
    expect(_eq(lib.stegoExtractDecrypt(out, key), secret), isTrue);
    expect(() => lib.stegoExtractDecrypt(out, Uint8List.fromList(List.filled(32, 0x22))),
        throwsException);
  });

  test('PhysicalSeal round-trip + wrong-aad', () {
    final keyMedia = ppm(0xABCDEF, 64, 64);
    final cover = ppm(0x123456);
    final out = '${tmp.path}/phys.ppm';
    final msg = _u('the photo is the key');
    final aad = _u('flutter-ctx');
    lib.physicalSeal(keyMedia, msg, aad, cover, out);
    expect(_eq(lib.physicalOpen(keyMedia, aad, out), msg), isTrue);
    expect(() => lib.physicalOpen(keyMedia, _u('wrong'), out), throwsException);
  });

  test('FEC corrects a single-bit flip (all schemes)', () {
    final data = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]);
    for (final scheme in [1, 2, 3]) {
      final enc = lib.fecEncode(data, scheme);
      enc[0] ^= 0x40;
      expect(_eq(lib.fecDecode(enc, scheme, data.length), data), isTrue);
    }
  });

  test('analysis: validity, tamper digest, hidden-data probe', () {
    final cover = ppm(0x99, 128, 128);
    final insp = lib.stegoInspect(cover);
    expect(insp.parses && insp.extMatches && insp.width == 128, isTrue);

    final d1 = lib.stegoContentDigest(cover);
    File(cover).writeAsBytesSync([0], mode: FileMode.append);
    final d2 = lib.stegoContentDigest(cover);
    expect(lib.secureEqual(d1, d2), isFalse); // tamper detected vs stored digest

    final clean = ppm(0x99, 128, 128);
    final stego = '${tmp.path}/as.ppm';
    lib.stegoEmbed(clean, _u('hi'), stego);
    final rep = lib.stegoDetectHidden(stego);
    expect(rep.cryptolibPayload && rep.note.isNotEmpty, isTrue);
  });

  test('ImageFactorSeal (C2) round-trip + wrong-image', () {
    final img = ppm(0xFEED, 64, 64);
    final cover = ppm(0xCAFE);
    final out = '${tmp.path}/ifs.ppm';
    final seed = Uint8List.fromList(List.filled(32, 0x42));
    final msg = _u('image is the second factor');
    lib.imageFactorSeal(seed, img, msg, Uint8List(0), cover, out);
    expect(_eq(lib.imageFactorOpen(seed, img, Uint8List(0), out), msg), isTrue);
    final other = ppm(0xBEEF, 64, 64);
    expect(() => lib.imageFactorOpen(seed, other, Uint8List(0), out), throwsException);
  });

  test('HpkeStegoSeal (C3) round-trip + wrong-recipient', () {
    final cover = ppm(0x4321);
    final out = '${tmp.path}/hss.ppm';
    final recip = lib.hpkeKeygen();
    final info = _u('session');
    final msg = _u('one session keys both');
    final enc = lib.hpkeStegoSeal(recip.publicKey, msg, Uint8List(0), info, cover, out);
    expect(_eq(lib.hpkeStegoOpen(recip.secretKey, enc, Uint8List(0), info, out), msg), isTrue);
    final mallory = lib.hpkeKeygen();
    expect(() => lib.hpkeStegoOpen(mallory.secretKey, enc, Uint8List(0), info, out),
        throwsException);
  });

  test('HMAC-DRBG (A3) handle', () {
    final seed = Uint8List.fromList(List.filled(32, 0x01));
    final d1 = lib.drbgInstantiate(seed, null, _u('beacon'));
    final a = d1.generate(64);
    expect(_eq(a, d1.generate(64)), isFalse); // forward-secret: blocks differ
    final d2 = lib.drbgInstantiate(seed, null, _u('beacon'));
    expect(_eq(a, d2.generate(64)), isTrue); // same seed reproduces
    d1.close();
    d2.close();
    expect(() => lib.drbgInstantiate(Uint8List.fromList([1, 2, 3])), throwsException);
  });

  test('Fortuna (A5) handle', () {
    final f = lib.fortunaNew();
    expect(() => f.generate(32), throwsException); // unseeded
    for (var i = 0; i < 40; i++) {
      f.addEntropy(i & 7, Uint8List.fromList(List.filled(16, i)));
    }
    f.reseed();
    expect(f.reseedCount() >= 1, isTrue);
    expect(f.generate(64).length, 64);
    f.close();
  });

  test('assess_file_health (A1)', () {
    final good = ppm(0x1357, 128, 128);
    final h = lib.assessFileHealth(good);
    expect(h.minEntropyPerByte > 1.0 && h.rctPassed && h.aptPassed && h.healthy(1.0), isTrue);
    // A constant-body PPM → flagged unhealthy.
    final flat = '${tmp.path}/flat.ppm';
    File(flat).writeAsBytesSync(<int>[...'P6\n64 64\n255\n'.codeUnits, ...List.filled(64 * 64 * 3, 0)]);
    expect(lib.assessFileHealth(flat).healthy(1.0), isFalse);
  });
}
