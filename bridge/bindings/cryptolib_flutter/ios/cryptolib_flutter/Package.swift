// swift-tools-version: 5.9
// CryptoLib Flutter plugin — Swift Package Manager manifest (iOS).
//
// FFI plugin: the CryptoLibC binary target is a self-contained DYNAMIC framework
// wrapping the prebuilt CryptoLib native library (libsodium / liboqs / blst /
// OpenSSL / secp256k1 / BLAKE3 statically inside). Declaring it as a dependency
// of this target makes Swift Package Manager link and embed it into the host
// app; Dart then resolves the C ABI at runtime via dart:ffi.
import PackageDescription

let package = Package(
    name: "cryptolib_flutter",
    platforms: [
        .iOS("13.0"),
    ],
    products: [
        // Flutter's generated package references the product by its hyphenated
        // plugin name.
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
