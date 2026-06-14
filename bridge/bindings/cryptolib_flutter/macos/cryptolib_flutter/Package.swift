// swift-tools-version: 5.9
// CryptoLib Flutter plugin — Swift Package Manager manifest (macOS).
//
// FFI plugin: the CryptoLibC binary target is a self-contained DYNAMIC framework
// wrapping the prebuilt CryptoLib native library. Declaring it as a dependency
// makes SPM link and embed it into the host app; Dart resolves the C ABI at
// runtime via dart:ffi.
import PackageDescription

let package = Package(
    name: "cryptolib_flutter",
    platforms: [
        .macOS("10.15"),
    ],
    products: [
        .library(name: "cryptolib-flutter", targets: ["cryptolib_flutter"]),
    ],
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "CryptoLibC",
            path: "CryptoLibC.xcframework"
        ),
        .target(
            name: "cryptolib_flutter",
            dependencies: ["CryptoLibC"]
        ),
    ]
)
