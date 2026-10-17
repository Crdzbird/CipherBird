# cipherbird example

A minimal Flutter app that proves the package works on a device. It warms the
library before the first frame, then runs a short self-test and shows one
row per check.

| Check | What it exercises |
|---|---|
| Library loaded | the bundled native library resolves and initialises |
| SHA-256 known answer | the hash of `abc` matches the published vector |
| SymmetricKey text round-trip | the key-committing AEAD through `encryptText` and `decryptText` |
| Hybrid signature verifies | Ed25519 plus ML-DSA-65 through `SigningKey` and `VerifyKey` |
| Hybrid KEM public-key encryption | X25519 plus ML-KEM-768 through `KemKeyPair.encryptTextFor` and `decryptText` |
| Flagship sealed messaging | two identities, `sealText` and `openText` |

The whole app is one file, [lib/main.dart](lib/main.dart). It prints
`CIPHERBIRD_SELFTEST: OK` or `CIPHERBIRD_SELFTEST: FAILED` to the console so
a headless run can be checked with `adb logcat` or `xcrun simctl launch
--console`.

## Run

```bash
flutter run
```

Pick an Android device, an iOS simulator or macOS when asked. The native
library comes with the package, so nothing has to be built or copied first.

## Startup

The example needs no startup call. It runs the app at once and gates the
first use of the engine on `CipherBird.ready`, which completes immediately
on Android, iOS and macOS and once the WebAssembly engine is compiled in the
browser, where the plugin registration has already started the download:

```dart
void main() => runApp(const ExampleApp());

FutureBuilder<void>(
  future: CipherBird.ready,
  builder: (context, snapshot) =>
      snapshot.connectionState == ConnectionState.done
          ? ResultsList(_checks())
          : const CircularProgressIndicator(),
)
```

Every call after that is synchronous. `await CipherBird.preload()` still
works for apps that call it: it loads the engine on the web and returns at
once elsewhere.

For an app to play with rather than a self-test, see the playground in the
package repository, which adds buttons to encrypt, corrupt and decrypt text,
sign and verify, encrypt to a public key and hash a passphrase on a worker.
