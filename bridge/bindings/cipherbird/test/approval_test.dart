import 'package:cipherbird/cipherbird.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  const web = bool.fromEnvironment('dart.library.js_interop');
  test('the approval boundary follows the build', () {
    final lib = CipherBird.instance;
    expect(lib.isWebBuild, web);
    expect(lib.approvedFor(ProtectedDataClass.ephemeral), isTrue);
    expect(lib.approvedFor(ProtectedDataClass.longLivedKeys), !web);
    expect(lib.approvedFor(ProtectedDataClass.cardData), !web);
    lib.requireApprovedFor(ProtectedDataClass.ephemeral);
    if (web) {
      expect(
        () => lib.requireApprovedFor(ProtectedDataClass.cardData),
        throwsUnsupportedError,
      );
      return;
    }
    lib.requireApprovedFor(ProtectedDataClass.cardData);
  });
}
