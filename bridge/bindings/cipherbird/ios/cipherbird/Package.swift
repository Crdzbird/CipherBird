// swift-tools-version: 5.9
// CipherBird Flutter plugin — Swift Package Manager manifest (iOS).
//
// FFI plugin: the CipherBird binary target is a self-contained DYNAMIC framework
// wrapping the prebuilt native engine (libsodium / liboqs / blst /
// OpenSSL / secp256k1 / BLAKE3 statically inside). Declaring it as a dependency
// of this target makes Swift Package Manager link and embed it into the host
// app; Dart then resolves the C ABI at runtime via dart:ffi.
import PackageDescription

let package = Package(
    name: "cipherbird",
    platforms: [
        .iOS("15.0"),  // the bundled CipherBird binary is built with -miphoneos-version-min=15.0,
    ],
    products: [
        // Flutter's generated package references the product by its hyphenated
        // plugin name.
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
