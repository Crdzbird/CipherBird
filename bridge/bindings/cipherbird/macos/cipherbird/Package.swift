// swift-tools-version: 5.9
// CryptoLib Flutter plugin — Swift Package Manager manifest (macOS).
//
// FFI plugin: the CryptoLibC binary target is a self-contained DYNAMIC framework
// wrapping the prebuilt CryptoLib native library. Declaring it as a dependency
// makes SPM link and embed it into the host app; Dart resolves the C ABI at
// runtime via dart:ffi.
import PackageDescription

let package = Package(
    name: "cipherbird",
    platforms: [
        .macOS("12.0"),  // the bundled CryptoLibC binary is built with -mmacosx-version-min=12.0,
    ],
    products: [
        .library(name: "cipherbird", targets: ["cipherbird"]),
    ],
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "CryptoLibC",
            path: "CryptoLibC.xcframework"
        ),
        .target(
            name: "cipherbird",
            dependencies: ["CryptoLibC"]
        ),
    ]
)
