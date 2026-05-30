# Using CryptoLib from the Flutter Android app

**This app runs on Android.** The native library is bundled as a prebuilt
`.so` per ABI and loaded by name; no host path is involved.

```bash
flutter build apk --debug        # or: flutter run -d <device>
```

## How it's wired

1. **Native library in `jniLibs`.** `libcryptolib_c.so` is shipped per ABI at
   `app/src/main/jniLibs/<abi>/libcryptolib_c.so`. The Android Gradle plugin
   packages everything under `jniLibs/` into the APK (`lib/<abi>/...`), and the
   Dart loader resolves it with `DynamicLibrary.open('libcryptolib_c.so')`
   (see `lib/cryptolib_ffi.dart`).

   Currently bundled: `arm64-v8a` (most devices + Apple-silicon emulators) and
   `x86_64` (Intel emulators).

   To refresh after rebuilding the native library:

   ```bash
   # from the repo root — build the Android slices
   make android                        # arm64-v8a + x86_64 → build/android-<abi>/

   cp build/android-arm64-v8a/libcryptolib_c.so \
      bridge/bindings/flutter/android/app/src/main/jniLibs/arm64-v8a/
   cp build/android-x86_64/libcryptolib_c.so \
      bridge/bindings/flutter/android/app/src/main/jniLibs/x86_64/
   ```

2. **compileSdk override.** `file_picker` 8 hardcodes `compileSdk 34`, which
   clashes with newer transitive deps (`flutter_plugin_android_lifecycle`) that
   require consumers to compile against API 36. `android/build.gradle.kts`
   forces `compileSdk 36` on every Android subproject in an `afterEvaluate`
   hook so the plugin AAR-metadata check passes.

## Sandbox paths

Like iOS, Android sandboxes app storage. `MediaEntropy` and the
`seal_from_file` / `open_from_file` helpers need a legal directory — use
`path_provider` (`getApplicationDocumentsDirectory()`,
`getTemporaryDirectory()`) rather than absolute paths.
