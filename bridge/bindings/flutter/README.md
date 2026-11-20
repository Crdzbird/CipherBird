# cipherbird_gui

The original CipherBird demo app: a Material 3 Flutter application that calls
the C ABI through its own hand-written `dart:ffi` file,
[`lib/cipherbird_ffi.dart`](lib/cipherbird_ffi.dart), with the native library
vendored by hand per platform.

It predates the [`cipherbird`](../cipherbird/README.md) plugin and is kept as a
reference for wiring the C ABI into a Flutter app without a plugin. A new app
should depend on `cipherbird` instead: the plugin ships the engines for
Android, iOS, macOS and the web, covers the whole C ABI (this app's binding
covers only the part its screens use) and has its own
[showcase](../cipherbird/example/README.md).

## Screens

Hashing, Encryption, Asymmetric, Media Entropy, Vault, Steganography, Advanced
and a client for the LavaRand entropy server in
[`../go/server`](../go/server).

## Run

Build the native library first, from the repository root:

```bash
make lib
```

Then start the app:

```bash
cd bridge/bindings/flutter
flutter run -d macos
```

Desktop loads the library from a path. The app takes it from the
`CIPHERBIRD_PATH` environment variable when that is set; otherwise type the
absolute path of `build/release/libcipherbird_c.dylib` into the field the app
shows and press Load Library. `setup_macos.sh` regenerates the macOS platform
folder if it is missing.

On Android and iOS the library is bundled into the app and loaded by name, so
no path is involved. The bundled binaries are not committed; build and copy
them as described in [`android/README.md`](android/README.md) and
[`ios/README.md`](ios/README.md).

## Check

```bash
make flutter
```

runs `flutter analyze` and `test/ffi_test.dart`, which calls the built library
through the app's binding.
