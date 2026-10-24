import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

Uint8List noisePpm(int size) {
  final body = Uint8List(size * size * 3);
  var s = 7;
  for (var i = 0; i < body.length; i++) {
    s ^= (s << 13) & 0xFFFFFFFF;
    s ^= s >> 17;
    s ^= (s << 5) & 0xFFFFFFFF;
    body[i] = s & 0xFF;
  }
  return Uint8List.fromList(
    ['P6\n$size $size\n255\n'.codeUnits, body].expand((b) => b).toList(),
  );
}

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  final msg = Uint8List.fromList('off the main thread'.codeUnits);

  for (final (name, runner) in [
    ('inline', const CipherBirdInlineRunner()),
    ('background', const CipherBirdIsolateRunner()),
  ]) {
    group('engine calls on the $name runner', () {
      test('ML-DSA, SLH-DSA and the hybrid signature verify', () async {
        final ml = await lib.mlDsaKeygenAsync(
          MlDsaLevel.level65,
          runner: runner,
        );
        final sig = await lib.mlDsaSignAsync(
          msg,
          ml.secretKey,
          MlDsaLevel.level65,
          runner: runner,
        );
        expect(
          lib.mlDsaVerify(msg, sig, ml.publicKey, MlDsaLevel.level65),
          isTrue,
        );
        final slh = await lib.slhDsaKeygenAsync(
          SlhDsaLevel.fast128,
          SlhDsaHash.shake,
          runner: runner,
        );
        final slhSig = await lib.slhDsaSignAsync(
          msg,
          slh.secretKey,
          SlhDsaLevel.fast128,
          SlhDsaHash.shake,
          runner: runner,
        );
        expect(
          lib.slhDsaVerify(
            msg,
            slhSig,
            slh.publicKey,
            SlhDsaLevel.fast128,
            SlhDsaHash.shake,
          ),
          isTrue,
        );
        final hy = lib.hybridSigKeygen();
        final hySig = await lib.hybridSigSignAsync(
          msg,
          hy.secretKey,
          runner: runner,
        );
        expect(lib.hybridSigVerify(msg, hySig, hy.publicKey), isTrue);
      });

      test('a Suite v2 envelope seals and opens', () async {
        final alice = lib.hybridSigKeygen();
        final bob = lib.xwingKeygen();
        final aad = Uint8List.fromList('ctx'.codeUnits);
        final env = await lib.suite2SealAsync(
          msg,
          bob.publicKey,
          alice.secretKey,
          aad: aad,
          runner: runner,
        );
        expect(
          await lib.suite2OpenAsync(
            env,
            bob.secretKey,
            bob.publicKey,
            alice.publicKey,
            aad: aad,
            runner: runner,
          ),
          msg,
        );
        expect(
          lib.suite2Open(
            env,
            bob.secretKey,
            bob.publicKey,
            alice.publicKey,
            aad: aad,
          ),
          msg,
        );
      });

      test('steganography on bytes and the file key', () async {
        final cover = noisePpm(128);
        const ppm = MediaFormat.ppmImage;
        final hidden = await lib.stegoEmbedBytesAsync(
          cover,
          ppm,
          msg,
          runner: runner,
        );
        expect(
          await lib.stegoExtractBytesAsync(hidden, ppm, runner: runner),
          msg,
        );
        expect(lib.stegoExtractBytes(hidden, ppm), msg);
        final key = lib.randomBytes(32);
        final sealed = await lib.stegoEmbedEncryptedBytesAsync(
          cover,
          ppm,
          msg,
          key,
          runner: runner,
        );
        expect(
          await lib.stegoExtractDecryptBytesAsync(
            sealed,
            ppm,
            key,
            runner: runner,
          ),
          msg,
        );
        expect(
          await lib.keyFromBytesAsync(cover, runner: runner),
          hasLength(32),
        );
      });
    });
  }
}
