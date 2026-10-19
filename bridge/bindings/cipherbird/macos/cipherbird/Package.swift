// swift-tools-version: 5.9
// CipherBird Flutter plugin — Swift Package Manager manifest (macOS).
//
// FFI plugin: the CipherBird binary target is a self-contained DYNAMIC framework
// wrapping the prebuilt native engine. Declaring it as a dependency
// makes SPM link and embed it into the host app; Dart resolves the C ABI at
// runtime via dart:ffi.
import PackageDescription

let package = Package(
    name: "cipherbird",
    platforms: [
        .macOS("12.0"),  // the bundled CipherBird binary is built with -mmacosx-version-min=12.0,
    ],
    products: [
        // Static. HardwareKey.swift declares an Objective-C class so the -ObjC
        // flag Flutter links with keeps its object file, and with it the
        // @_cdecl functions Dart resolves through DynamicLibrary.process().
        .library(name: "cipherbird", targets: ["cipherbird"]),
    ],
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "CipherBird",
            path: "CipherBird.xcframework"
        ),
        .target(
            name: "cipherbird",
            dependencies: ["CipherBird"]
        ),
    ]
)
