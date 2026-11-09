import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  const isWeb = bool.fromEnvironment('dart.library.js_interop');
  Uint8List bytes(String s) => Uint8List.fromList(utf8.encode(s));
  Matcher status(TokenStatus s) =>
      throwsA(isA<TokenException>().having((e) => e.status, 'status', s));
  final invalid = status(TokenStatus.invalid);
  final argument = status(TokenStatus.argument);
  final unknown = status(TokenStatus.format);
  final unavailable = status(TokenStatus.unavailable);

  late final List<TokenFormat> table;
  var engineHasTokens = true;
  try {
    table = lib.tokenFormats();
  } on Object {
    engineHasTokens = false;
  }
  if (!engineHasTokens) {
    test('the bundled engine predates the generic token API', () {
      expect(isWeb, isTrue);
    }, skip: 'the web engine in this checkout has no token table yet');
    return;
  }
  bool available(String format) =>
      table.firstWhere((f) => f.format == format).available;

  group('generic token API', () {
    test('the table lists every format with its sizes', () {
      expect(table.map((f) => f.format).toSet(), {
        'v4.local',
        'cb1.local',
        'cb1.public',
      });
      for (final f in table) {
        expect(f.isPublic, f.format.endsWith('.public'));
        expect(f.maxInputBytes, 1 << 26);
        if (f.isPublic) {
          expect(
            [f.publicKeyBytes, f.secretKeyBytes, f.signatureBytes],
            [
              1984,
              4096,
              3373,
            ],
          );
          continue;
        }
        expect(f.keyBytes, 32);
      }
      expect(available('v4.local'), isTrue);
      expect(lib.tokens.formats().length, table.length);
    });

    test('unknown and unavailable formats are told apart', () {
      final key = lib.tokenKeygen('v4.local').secretKey;
      expect(() => lib.tokenIssue('v9.local', key, bytes('m')), unknown);
      expect(() => lib.tokenAccept('v9.local', 'v9.local.AAAA', key), unknown);
      expect(() => lib.tokenKeygen('v4.secret'), unknown);
      for (final f in table.where((f) => !f.available)) {
        expect(() => lib.tokenIssue(f.format, key, bytes('m')), unavailable);
        expect(() => lib.tokenKeygen(f.format), unavailable);
      }
    });

    test('keygen, issue and accept round-trip in every available format', () {
      for (final f in table.where((f) => f.available)) {
        final k = lib.tokenKeygen(f.format);
        final acceptKey = f.isPublic ? k.publicKey! : k.secretKey;
        expect(k.isPair, f.isPublic);
        expect(k.secretKey.length, f.isPublic ? 4096 : 32);
        final m = bytes('{"sub":"alice"}');
        final footer = bytes('{"kid":"k1"}');
        final implicit = bytes('audience');
        final tok = lib.tokenIssue(
          f.format,
          k.secretKey,
          m,
          footer: footer,
          implicit: implicit,
        );
        expect(tok, startsWith('${f.format}.'));
        expect(
          lib.tokenAccept(
            f.format,
            tok,
            acceptKey,
            expectedFooter: footer,
            implicit: implicit,
          ),
          m,
        );
        expect(
          lib.tokens.accept(
            f.format,
            tok,
            acceptKey,
            expectedFooter: footer,
            implicit: implicit,
          ),
          m,
        );
        expect(
          () => lib.tokenAccept(
            f.format,
            tok,
            acceptKey,
            expectedFooter: bytes('{"kid":"k2"}'),
            implicit: implicit,
          ),
          invalid,
        );
        expect(
          () => lib.tokenAccept(
            f.format,
            tok,
            acceptKey,
            expectedFooter: footer,
          ),
          invalid,
        );
        final flipped =
            tok.substring(0, tok.length - 1) + (tok.endsWith('A') ? 'B' : 'A');
        expect(
          () => lib.tokenAccept(
            f.format,
            flipped,
            acceptKey,
            expectedFooter: footer,
            implicit: implicit,
          ),
          invalid,
        );
        final other = lib.tokenKeygen(f.format);
        expect(
          () => lib.tokenAccept(
            f.format,
            tok,
            f.isPublic ? other.publicKey! : other.secretKey,
            expectedFooter: footer,
            implicit: implicit,
          ),
          invalid,
        );
        expect(
          () => lib.tokenIssue(f.format, k.secretKey.sublist(1), m),
          argument,
        );
        expect(lib.tokenPeekFormat(tok), f.format);
        expect(lib.tokenPeekFooter(tok), footer);
        final bare = lib.tokenIssue(f.format, k.secretKey, Uint8List(0));
        expect('.'.allMatches(bare).length, 2);
        expect(lib.tokenPeekFooter(bare), isNull);
        expect(lib.tokenAccept(f.format, bare, acceptKey), isEmpty);
      }
    });

    test('the caller names the format and the header never chooses', () {
      final key = lib.tokenKeygen('v4.local').secretKey;
      final v4 = lib.tokenIssue('v4.local', key, bytes('m'));
      final relabelled = 'cb1.local.${v4.substring('v4.local.'.length)}';
      expect(() => lib.tokenAccept('v4.local', relabelled, key), invalid);
      expect(lib.pasetoV4LocalDecrypt(v4, key), bytes('m'));
      if (available('cb1.local')) {
        final cb1 = lib.tokenIssue('cb1.local', key, bytes('m'));
        expect(() => lib.tokenAccept('v4.local', cb1, key), invalid);
        expect(() => lib.tokenAccept('cb1.local', v4, key), invalid);
        expect(lib.tokenAccept('cb1.local', cb1, key), bytes('m'));
        expect(lib.cb1LocalDecrypt(cb1, key), bytes('m'));
        final named = lib.cb1LocalEncrypt(key, bytes('m'));
        expect(lib.tokenAccept('cb1.local', named, key), bytes('m'));
      }
      expect(lib.tokenPeekFormat('v9.public.abc'), 'v9.public');
      expect(lib.tokenPeekFormat('v4.secret.abc'), '');
      expect(lib.tokenPeekFormat(''), '');
      expect(() => lib.tokenPeekFooter('v4.local.abc.a=b'), invalid);
      expect(() => lib.tokenPeekFooter('nonsense'), invalid);
      expect(lib.tokenPeekFooter('v4.local.abc.a2lk'), bytes('kid'));
      expect(lib.tokens.peekFormat(v4), 'v4.local');
    });

    test('the common-schema vectors accept through the generic calls', () {
      if (isWeb) {
        return;
      }
      Uint8List unhex(String h) => Uint8List.fromList(
        List.generate(
          h.length ~/ 2,
          (i) => int.parse(h.substring(2 * i, 2 * i + 2), radix: 16),
        ),
      );
      Uint8List? opt(Object? s) {
        final text = s! as String;
        return text.isEmpty ? null : bytes(text);
      }

      final dir = Directory('../../../tests/vectors/tokens');
      final files = dir
          .listSync()
          .whereType<File>()
          .where((f) => f.path.endsWith('.json'))
          .toList();
      expect(files.length, greaterThanOrEqualTo(3));
      for (final file in files) {
        final v = jsonDecode(file.readAsStringSync()) as Map<String, Object?>;
        final format = v['format']! as String;
        final cases = (v['cases']! as List).cast<Map<String, Object?>>();
        expect(cases, isNotEmpty);
        if (!available(format)) {
          continue;
        }
        final pub = format.endsWith('.public');
        for (final t in cases) {
          final keyHex = (pub ? t['public-key'] : t['key'])?.toString();
          final name = t['name']! as String;
          if (keyHex == null || keyHex.isEmpty) {
            expect(t['expect-fail'], isTrue, reason: name);
            continue;
          }
          final k = unhex(keyHex);
          Uint8List run() => lib.tokenAccept(
            format,
            t['token']! as String,
            k,
            expectedFooter: opt(t['footer']),
            implicit: opt(t['implicit-assertion']),
          );
          if (t['expect-fail']! as bool) {
            expect(run, invalid, reason: name);
            continue;
          }
          expect(utf8.decode(run()), t['payload'], reason: name);
          expect(lib.tokenPeekFormat(t['token']! as String), format);
          expect(
            lib.tokenPeekFooter(t['token']! as String) ?? Uint8List(0),
            bytes(t['footer']! as String),
          );
          if (pub) {
            final again = lib.tokenIssue(
              format,
              unhex(t['secret-key']! as String),
              bytes(t['payload']! as String),
              footer: opt(t['footer']),
              implicit: opt(t['implicit-assertion']),
            );
            expect(
              lib.tokenAccept(
                format,
                again,
                k,
                expectedFooter: opt(t['footer']),
                implicit: opt(t['implicit-assertion']),
              ),
              bytes(t['payload']! as String),
            );
          }
        }
      }
    });
  });
}
