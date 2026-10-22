import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';
import 'package:cipherbird_example/checks/check.dart';
import 'package:cipherbird_example/util/bytes.dart';

/// What this build is and what it is approved for.
final class OverviewChecks {
  const OverviewChecks._();

  static List<Check> build(CipherBird lib) => [
    Check('Engine loaded', () async => 'CipherBird ${lib.version()}'),
    Check(
      'Build kind',
      () async =>
          lib.isWebBuild ? 'WebAssembly in the browser' : 'native engine',
    ),
    for (final c in ProtectedDataClass.values)
      Check('Approved for ${c.name}', () async {
        final ok = lib.approvedFor(c);
        if (!ok) {
          throw const SkipCheck(
            'not approved on the web build (threat model 9.5)',
          );
        }
        return 'requireApprovedFor(${c.name}) passes';
      }),
    Check('Validated module on this platform', () async {
      try {
        final info = await DeviceFips.platform().module();
        final extra = info.providers.isEmpty ? '' : ' ${info.providers}';
        return '${info.module} on ${info.platform}$extra';
      } on FipsException catch (e) {
        throw SkipCheck(e.message);
      }
    }),
    Check('Default security profile', () async {
      const p = SecurityProfile.balanced;
      demand(p.hpkeKem == HpkeKem.xWing, 'X-Wing expected');
      return 'KEM ${p.hpkeKem.name}, suite ${p.suite2.name}, ML-KEM ${p.mlKem.name}';
    }),
  ];
}
