# cryptolib_flutter

CryptoLib for Flutter — hashing, AEAD, asymmetric, vaults, post-quantum
(ML-KEM / ML-DSA / SLH-DSA), a hybrid X25519+ML-KEM-768 KEM, BLS, and a keyring,
exposed via `dart:ffi`.

The native library is **bundled per platform and loaded automatically** — no
path, no manual setup. iOS/macOS vendor the prebuilt `CryptoLibC.xcframework`
(a self-contained dynamic framework: libsodium, liboqs, blst, OpenSSL libcrypto,
secp256k1 and BLAKE3 are statically inside); Android ships `libcryptolib_c.so`
in `jniLibs`. The package is about 28 MB compressed for that reason.

## Usage

```dart
import 'package:cryptolib_flutter/cryptolib_flutter.dart';

final lib = CryptoLib.load(); // platform default: process() on iOS, soname elsewhere
lib.init();

final digest = lib.sha256(Uint8List.fromList('abc'.codeUnits));

// Post-quantum hybrid key agreement (secure if either half survives):
final kp = lib.hybridKemKeygen();
final (ciphertext, ssEnc) = lib.hybridKemEncapsulate(kp.publicKey);
final ssDec = lib.hybridKemDecapsulate(ciphertext, kp.secretKey); // == ssEnc
```

## Platform support

| Platform | Status |
|---|---|
| Android (arm64-v8a, x86_64) | ✅ bundled, verified on device |
| iOS 15+ (arm64 device + arm64 simulator) | ✅ bundled, verified on simulator |
| macOS 12+ (Apple silicon, arm64) | ✅ bundled, verified build |
| Linux, Windows, web | ❌ not in this release (no prebuilt library shipped) |
| Android armeabi-v7a / x86, Intel macOS | ❌ not in this release |

### iOS simulator note (Apple-silicon only)

The bundled xcframework ships an **arm64** iOS-simulator slice (Apple-silicon
hosts). `flutter run` / `flutter test` on an arm64 simulator works out of the
box. A *generic* `flutter build ios --simulator` also tries to compile `x86_64`
and will fail, because there is no x86_64 simulator slice. Two options for a
fully universal build:

1. **Ship a universal simulator slice** (arm64 + x86_64) — rebuild the iOS
   `iphonesimulator` dependency + cryptolib slices for both archs and `lipo`
   them. (Recommended before publishing.)
2. **Exclude x86_64 in the consuming app** via a Podfile `post_install` hook:
   ```ruby
   post_install do |installer|
     installer.pods_project.targets.each do |t|
       t.build_configurations.each do |c|
         c.build_settings['EXCLUDED_ARCHS[sdk=iphonesimulator*]'] = 'x86_64'
       end
     end
   end
   ```

## Updating the bundled binaries

The prebuilt binaries are **committed** (this package is published from the
repository tree, and pub.dev consumers get the binary from the package itself).
They go stale after any C ABI change — the Dart side binds every symbol eagerly,
so a stale binary fails at `CryptoLib.load()`. Rebuild from the repo root:

```bash
# Android: cross-compiles the dependencies once, then libcryptolib_c.so
bash scripts/android/build_all.sh arm64-v8a x86_64
cp build/android/arm64-v8a/libcryptolib_c.so android/src/main/jniLibs/arm64-v8a/
cp build/android/x86_64/libcryptolib_c.so    android/src/main/jniLibs/x86_64/

# iOS device + simulator + macOS: one xcframework, vendored twice
make ios
rm -rf ios/cryptolib_flutter/CryptoLibC.xcframework macos/cryptolib_flutter/CryptoLibC.xcframework
cp -R CryptoLib.xcframework ios/cryptolib_flutter/CryptoLibC.xcframework
cp -R CryptoLib.xcframework macos/cryptolib_flutter/CryptoLibC.xcframework
```

Then check the symbol count matches the header before publishing:

```bash
grep -c '^CRYPTO_API' bridge/cryptolib_c.h
nm -gU ios/cryptolib_flutter/CryptoLibC.xcframework/ios-arm64/CryptoLibC.framework/CryptoLibC | grep -c ' T _cryptolib_'
strings android/src/main/jniLibs/arm64-v8a/libcryptolib_c.so | grep -c '^cryptolib_'
```

## License and attribution

MIT — see [LICENSE](LICENSE). The license requires that the copyright notice
(credit to the author, Crdzbird) is kept in every copy or substantial portion
of this software, including apps and libraries that bundle it.
