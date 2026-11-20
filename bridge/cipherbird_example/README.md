# cipherbird_example

The smallest Flutter app that calls the CipherBird C ABI directly. Its binding,
[`lib/cipherbird_ffi.dart`](lib/cipherbird_ffi.dart), looks up nine functions by
hand with `dart:ffi`, and the single screen runs two checks: a BLAKE2b hash and
an XChaCha20-Poly1305 encrypt and decrypt round trip.

It is kept as the minimal reference for loading the library from a Flutter app
without a plugin (Android, iOS, macOS and Linux loaders are in the binding
file). An application should use the
[`cipherbird`](../bindings/cipherbird/README.md) plugin instead, which ships
the engines and the whole API.

## Native library

The app expects the library where each platform loads it from, and none of
these binaries are committed:

- Android: `android/app/src/main/jniLibs/<abi>/libcryptolib_c.so`, built with
  `make android` from the repository root.
- iOS: `ios/Frameworks/CipherBird.xcframework`, built with
  `./scripts/ios/build_all.sh`; the Runner project already references it and
  the symbols are found in the app's own image.

## Run

```bash
flutter run -d <device id>
```
