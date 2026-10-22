import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/fips_backend.dart';
import 'package:cipherbird/src/hardware/fips/unsupported_fips_backend.dart';

/// The browser has no validated module reachable from the plugin.
FipsBackend createPlatformFipsBackend({CipherBird? engine}) =>
    const UnsupportedFipsBackend('web');
