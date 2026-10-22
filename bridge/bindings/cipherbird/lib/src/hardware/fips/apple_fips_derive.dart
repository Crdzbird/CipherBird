import 'dart:convert';
import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/apple_fips_call.dart';
import 'package:cipherbird/src/hardware/fips/fips_module_info.dart';

/// Module description and HKDF through the Swift side.
final class AppleFipsDerive {
  const AppleFipsDerive._();

  static final Uint8List _none = Uint8List(0);

  /// `corecrypto via CryptoKit; OS version` from the Swift side.
  static FipsModuleInfo module() {
    final parts = utf8
        .decode(AppleFipsCall.run([], (b, _, o, l) => b.module(o, l)))
        .split('; ');
    return FipsModuleInfo(module: parts.first, platform: parts.last);
  }

  static Uint8List hkdf(
    FipsHash hash,
    Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    int count,
  ) {
    final s = salt ?? _none, f = info ?? _none;
    return AppleFipsCall.run(
      [ikm, s, f],
      (b, i, o, l) => b.hkdf(
        hash.value,
        i[0],
        ikm.length,
        i[1],
        s.length,
        i[2],
        f.length,
        count,
        o,
        l,
      ),
    );
  }
}
