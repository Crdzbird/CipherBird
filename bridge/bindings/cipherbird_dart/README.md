# cipherbird_dart

CipherBird for plain Dart: servers, command-line tools and desktop programs.
It is the same code as the `cipherbird` Flutter plugin, generated from the
same source tree, with the native CryptoLib library bundled inside the
package for the host platform instead of inside an app.

Everything in the `cipherbird` README applies here: the easy-mode classes,
the full API groups, security profiles, recipes, the extension points and the
wire formats. This file covers only what differs.

## Install

```yaml
dependencies:
  cipherbird_dart: ^1.0.0
```

```dart
import 'package:cipherbird_dart/cipherbird_dart.dart';

final key = SymmetricKey.generate();
final box = key.encryptText('meet at dawn');
print(key.decryptText(box));
```

No setup call is needed. The first use of `CryptoLib.instance` opens the
bundled library.

## How the native library is found

`CryptoLib.load()` resolves the library in this order:

1. An explicit path passed to `load`.
2. The `CRYPTOLIB_DYLIB` environment variable.
3. The bundled copy under `native/<os>-<arch>/`, located through the
   `.dart_tool/package_config.json` of the running program, then the current
   directory, then the directory above the running script.
4. `libcryptolib_c.so` on the loader path (Linux), or the process image.

A compiled executable (`dart compile exe`) has no package config next to it,
so pass the path explicitly or set the environment variable, and ship the
library file with the binary.

## Platforms in this release

| Platform | Status |
|---|---|
| macOS, Apple silicon | bundled (`native/darwin-arm64`) |
| Linux x64, Windows x64, Intel macOS | not bundled in this release; build the library from the repository and point `CRYPTOLIB_DYLIB` at it |

The bundled slot is refreshed with `make bundle` from the repository root.

## Benchmarks

See the `cipherbird` README for the comparison against pure-Dart packages.
The harness lives in `benchmark/bench.dart` of this package:

```bash
cd benchmark && dart pub get && dart run bench.dart
```

## Verifying

`dart test` runs the same 104 tests as the Flutter plugin against the
bundled library. The `bin/` scripts are the verification harnesses the
repository's Makefile drives (`make dart-security`, `make dart-noise`,
`make recipe-interop`).

## License

MIT, see [LICENSE](LICENSE). The copyright notice credits the author
Crdzbird and must be kept in every copy or substantial portion of the
software.
