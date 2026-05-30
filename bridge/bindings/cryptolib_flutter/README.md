# cryptolib_flutter

CryptoLib for Flutter — hashing, AEAD, asymmetric, vaults, post-quantum
(ML-KEM / ML-DSA / SLH-DSA), a hybrid X25519+ML-KEM-768 KEM, BLS, and a keyring,
exposed via `dart:ffi`.

The native library is **bundled per platform and loaded automatically** — no
path, no manual setup. iOS/macOS vendor the prebuilt `CryptoLib.xcframework`;
Android ships `libcryptolib_c.so` in `jniLibs`.

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
| Android (arm64-v8a, x86_64) | ✅ verified on device |
| iOS (arm64 device + arm64 simulator) | ✅ verified on simulator |
| macOS (arm64) | vendored; build supported |

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

```bash
# from the repo root
make android                                   # rebuild .so (arm64-v8a + x86_64)
cp build/android-arm64-v8a/libcryptolib_c.so android/src/main/jniLibs/arm64-v8a/
cp build/android-x86_64/libcryptolib_c.so    android/src/main/jniLibs/x86_64/

make ios                                       # rebuild CryptoLib.xcframework
cp -R CryptoLib.xcframework ios/ && cp -R CryptoLib.xcframework macos/
```
