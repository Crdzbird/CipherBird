# Using CryptoLib from a Flutter iOS app

**This app already runs on iOS.** `CryptoLib.xcframework` is vendored at
`ios/Frameworks/` and wired into the Runner target, and the Dart loader
(`lib/cryptolib_ffi.dart`) automatically uses `DynamicLibrary.process()` on
iOS. Build and run as usual:

```bash
flutter build ios --simulator        # or: flutter run -d <simulator>
```

The native symbols come from the static archive inside the XCFramework, which
is force-loaded into the app binary (`-ObjC -all_load`) so Dart FFI can resolve
them at runtime — you cannot `dlopen` an arbitrary filesystem path on iOS.

The rest of this doc explains how that wiring was done, so you can reproduce it
in **another** Flutter iOS app.

---

## 1. Build the XCFramework

```bash
# From the repo root
./scripts/ios/build_all.sh   # produces ./CryptoLib.xcframework
```

First run fetches source tarballs and builds every dep from scratch —
about 15 min per slice. Subsequent runs skip unchanged deps thanks to
per-slice `.built` stamp files.

---

## 2. Vendor the XCFramework into your Flutter iOS Runner

From your Flutter app's root:

```bash
mkdir -p ios/Frameworks
cp -R /path/to/cryptolib/CryptoLib.xcframework ios/Frameworks/
```

Then wire it into the Runner target. The scripted way (what this app uses) is
`ios/add_xcframework.rb` — it's idempotent and sets everything the linker needs:

```bash
cd ios && ruby add_xcframework.rb   # needs the `xcodeproj` gem
```

It adds the framework reference, attaches it to the **Frameworks** and **Embed
Frameworks** build phases (Embed & Sign), sets `FRAMEWORK_SEARCH_PATHS`, adds
`-ObjC -all_load` to `OTHER_LDFLAGS` (so the static archive isn't dead-stripped —
critical, since nothing references the symbols at compile time), and excludes the
`x86_64` simulator arch (only the `arm64` simulator slice ships).

Prefer the GUI? In Xcode: **Runner** target → **General** → **Frameworks,
Libraries, and Embedded Content** → `+` → **Add Other… → Add Files…** → pick
`ios/Frameworks/CryptoLib.xcframework`, set **Embed & Sign**, then add
`-ObjC -all_load` under **Build Settings → Other Linker Flags**.

---

## 3. Update the Dart FFI lookup

Flutter macOS loads `libcryptolib_c.dylib` via
`DynamicLibrary.open('libcryptolib_c.dylib')`. On iOS, the static
archive from the XCFramework is linked directly into the app binary,
so use `DynamicLibrary.process()` instead:

```dart
import 'dart:ffi';
import 'dart:io' show Platform;

final DynamicLibrary _lib = Platform.isIOS
    ? DynamicLibrary.process()
    : DynamicLibrary.open(_defaultDylibName());

String _defaultDylibName() {
  if (Platform.isMacOS) return 'libcryptolib_c.dylib';
  if (Platform.isWindows) return 'cryptolib_c.dll';
  return 'libcryptolib_c.so';  // Linux / Android
}
```

Only the library-loading line changes — every `.lookup<NativeFunction<...>>('cryptolib_*')`
call in the existing bindings works unchanged because the symbols are now
part of the app's own image.

---

## 4. Use sandbox-legal filesystem paths

`MediaEntropy` and `seal_from_file` / `open_from_file` read and write to
disk. iOS sandboxes apps — `/tmp` and `/var/*` outside the container are
off-limits. Use `path_provider` (or the equivalent) to get a legal dir:

```dart
import 'package:path_provider/path_provider.dart';

final docs = await getApplicationDocumentsDirectory();
final photoPath = '${docs.path}/secret.jpg';

// … copy or write the photo to photoPath …

final packet = lib.sealFromFile(photoPath, 'classified message', 'ctx');
```

`getTemporaryDirectory()`, `getApplicationDocumentsDirectory()`, and
`getApplicationSupportDirectory()` all work. Avoid `Directory.systemTemp`
— that returns `/tmp`, which is inaccessible on iOS.

---

## 5. App Store compliance notes

- The XCFramework is **self-contained** (all deps statically linked) and
  ships no `.dylib`, so no `Embed & Sign` of third-party dylibs is
  required beyond the framework itself.
- Post-quantum algorithms (ML-KEM / ML-DSA / SLH-DSA) are enabled in the
  prebuilt framework. They are purely software — no export-control flags
  to declare beyond the usual "uses standard encryption" self-attestation.
- `libsodium` and `libcrypto` also compile in. Export-compliance docs
  for "app uses encryption" apply as they would for any app shipping
  libsodium/OpenSSL.
