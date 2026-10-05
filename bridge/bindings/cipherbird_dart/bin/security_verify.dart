// Verifies the grouped API, the algorithm enums, and the composable
// SecurityProfile / CipherBirdRecipe pipeline.
//   dart run bin/security_verify.dart [path-to-libcipherbird.dylib]
import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';

int _failures = 0;
void check(bool ok, String label) {
  stdout.writeln('${ok ? "  ok  " : " FAIL "} $label');
  if (!ok) _failures++;
}

bool throws(void Function() f) {
  try {
    f();
    return false;
  } catch (_) {
    return true;
  }
}

bool eq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

Uint8List noisePpm(int w, int h, int seed) {
  final head = 'P6\n$w $h\n255\n'.codeUnits;
  final body = Uint8List(w * h * 3);
  var s = seed == 0 ? 1 : seed;
  for (var i = 0; i < body.length; i++) {
    s ^= (s << 13) & 0xFFFFFFFF;
    s ^= s >> 17;
    s ^= (s << 5) & 0xFFFFFFFF;
    body[i] = s & 0xFF;
  }
  return Uint8List.fromList([...head, ...body]);
}

void main(List<String> args) {
  final path = args.isNotEmpty ? args[0] : null;
  final lib = CipherBird.load(path);
  lib.init();
  final dir = Directory.systemTemp.createTempSync('cl_sec_');
  final secret = Uint8List.fromList('composed protection'.codeUnits);
  CipherBirdRecipe cheap(CipherBirdRecipe r) =>
      r.argon2Cost(ops: 1, memoryBytes: 8 * 1024 * 1024);

  // ── Grouped API ────────────────────────────────────────────────────────────
  check(
    eq(
      lib.hash.sha256(Uint8List.fromList('abc'.codeUnits)),
      lib.sha256(Uint8List.fromList('abc'.codeUnits)),
    ),
    'grouped hash.sha256 == flat sha256',
  );
  final kp = lib.pq.mlKem.keygen(MlKemLevel.level768);
  final (ct, ss) = lib.pq.mlKem.encapsulate(kp.publicKey, MlKemLevel.level768);
  check(
    eq(lib.pq.mlKem.decapsulate(ct, kp.secretKey, MlKemLevel.level768), ss),
    'pq.mlKem round-trip with enum level',
  );
  check(lib.rng.bytes(32).length == 32, 'rng.bytes');

  // ── Enums ──────────────────────────────────────────────────────────────────
  check(MlKemLevel.level1024.nistCategory == 5, 'MlKemLevel metadata');
  check(
    SecurityProfile.maximum.mlKem == MlKemLevel.level1024 &&
        SecurityProfile.maximum.sealedTier == SealedTier.fortress,
    'maximum profile picks the strongest options',
  );
  check(
    SecurityProfile.maximum.cascade.last == ProtectionLayer.committing,
    'maximum cascade ends key-committing',
  );

  // ── Recipe round-trips ─────────────────────────────────────────────────────
  final r1 = cheap(
    lib.maximumSecurity().withPassphrase('correct horse battery staple'),
  );
  check(
    eq(r1.open(r1.seal(secret)), secret),
    'maximum + passphrase round-trip',
  );

  final key = lib.rng.bytes(32);
  final r2 = lib.recipe().withKey(key);
  check(eq(r2.open(r2.seal(secret)), secret), 'raw key round-trip');

  final keyFile = '${dir.path}/key.ppm';
  File(keyFile).writeAsBytesSync(noisePpm(96, 96, 0x5EED));
  final sealer = lib.recipe().withKeyFile(keyFile);
  final opener = lib.recipe().withKeyFile(keyFile);
  check(
    eq(opener.open(sealer.seal(secret)), secret),
    'key file is reproducible across recipe objects',
  );

  // ── Composition ────────────────────────────────────────────────────────────
  final id = lib.ed25519Keygen();
  final signed = lib
      .recipe(SecurityProfile.high)
      .withKey(key)
      .signedBy(id.secretKey)
      .verifiedBy(id.publicKey);
  check(eq(signed.open(signed.seal(secret)), secret), 'signed round-trip');

  final impostor = lib.ed25519Keygen();
  final wrongVerifier = lib
      .recipe()
      .withKey(key)
      .verifiedBy(impostor.publicKey);
  final sealedByReal = lib
      .recipe()
      .withKey(key)
      .signedBy(id.secretKey)
      .seal(secret);
  check(
    throws(() => wrongVerifier.open(sealedByReal)),
    'wrong signer rejected',
  );
  check(
    throws(() => lib.recipe().withKey(key).open(sealedByReal)),
    'signed envelope refuses to open unverified',
  );

  final fecR = lib.recipe().withKey(key).withFec(FecScheme.repetition3);
  final fenv = fecR.seal(secret);
  fenv[fenv.length ~/ 2] ^= 1;
  check(eq(fecR.open(fenv), secret), 'FEC corrects a flipped bit');

  final cover = '${dir.path}/cover.ppm', out = '${dir.path}/carrier.ppm';
  File(cover).writeAsBytesSync(noisePpm(256, 256, 0x0FF1CE));
  final carrierR = cheap(
    lib.maximumSecurity().withPassphrase('a long passphrase'),
  );
  carrierR.sealIntoCarrier(secret, coverPath: cover, outputPath: out);
  check(
    eq(carrierR.openFromCarrier(out), secret),
    'pipeline hides itself in a carrier',
  );
  check(
    lib.stego.inspect(out).format == MediaFormat.ppmImage,
    'carrier is still a valid image',
  );

  // ── Fails closed ───────────────────────────────────────────────────────────
  final tamper = lib.recipe(SecurityProfile.high).withKey(key);
  final tenv = tamper.seal(secret);
  tenv[tenv.length - 1] ^= 1;
  check(throws(() => tamper.open(tenv)), 'flipped ciphertext byte rejected');

  final henv = tamper.seal(secret);
  henv[7] = 1; // claim one layer instead of two
  check(
    throws(() => tamper.open(henv)),
    'tampered header rejected (descriptor is AAD)',
  );

  check(
    throws(
      () => cheap(
        lib.recipe().withPassphrase('wrong'),
      ).open(cheap(lib.recipe().withPassphrase('right')).seal(secret)),
    ),
    'wrong passphrase rejected',
  );
  check(
    throws(() => lib.recipe().withKey(Uint8List(31))),
    'short key refused up front',
  );

  dir.deleteSync(recursive: true);
  stdout.writeln(_failures == 0 ? '\nALL PASS' : '\n$_failures FAILURE(S)');
  exit(_failures == 0 ? 0 : 1);
}
