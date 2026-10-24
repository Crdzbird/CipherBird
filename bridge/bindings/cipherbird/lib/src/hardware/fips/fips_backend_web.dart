import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/fips_backend.dart';
import 'package:cipherbird/src/hardware/fips/web/web_crypto_fips_backend.dart';

/// In the browser the facade runs on WebCrypto, the platform's own crypto;
/// `module()` says it is not a validated module as exposed to pages.
FipsBackend createPlatformFipsBackend({CipherBird? engine}) =>
    const WebCryptoFipsBackend();
