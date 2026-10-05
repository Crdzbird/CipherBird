// CryptoLib Flutter plugin (Swift Package Manager).
//
// This is an FFI plugin: there is no method channel and no native plugin class.
// The CryptoLibC binary target (a dynamic framework wrapping the prebuilt
// CryptoLib native library) is a dependency of this target purely so Swift
// Package Manager links and EMBEDS it into the host app. At runtime Dart
// resolves the C ABI via dart:ffi (DynamicLibrary.process()), and the native
// library is warmed off the main isolate by CryptoLib.preload() on the Dart
// side — no native warm-up call here (a link-time reference to a binary-target
// symbol is not propagated by Flutter's SPM integration).
import Foundation
