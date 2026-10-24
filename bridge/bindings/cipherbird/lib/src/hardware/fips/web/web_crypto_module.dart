import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import 'package:cipherbird/src/hardware/fips/fips_module_info.dart';

/// What the WebCrypto backend reports: the platform's crypto, named as
/// such, with the browser's user agent as the platform.
final class WebCryptoModule {
  const WebCryptoModule();

  static const _served = [
    'digest',
    'hmac',
    'hkdf',
    'pbkdf2',
    'aesGcm',
    'ec',
    'ecdsa',
    'random',
  ];

  FipsModuleInfo describe() => FipsModuleInfo(
    module:
        'WebCrypto, the browser platform crypto, not a validated module as '
        'exposed to pages',
    platform: globalContext
        .getProperty<JSObject>('navigator'.toJS)
        .getProperty<JSString>('userAgent'.toJS)
        .toDart,
    providers: {for (final p in _served) p: 'WebCrypto'},
  );
}
