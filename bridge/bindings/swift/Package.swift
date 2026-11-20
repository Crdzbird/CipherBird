// swift-tools-version: 5.10
//
// CipherBird Swift Package
// ━━━━━━━━━━━━━━━━━━━━━━━━
// Consumes the prebuilt CipherBird.xcframework at the repo root (produced by
// `./scripts/ios/build_all.sh`). The XCFramework bundles libcipherbird_c plus
// every dependency (libsodium, libblake3, libcrypto, liboqs, libblst) as a
// single self-contained static archive per slice — no dylib loading, no
// RPATH games.
//
// Supported platforms (matching XCFramework slices):
//   • iOS 15+    device (arm64)
//   • iOS 15+    simulator (arm64 — Apple Silicon Macs)
//   • macOS 14+  (arm64)
//
// Add this package to another project with e.g.:
//
//     dependencies: [ .package(path: "path/to/cipherbird/bridge/swift") ]
//
// then
//
//     import CipherBirdC    // raw C FFI (cipherbird_blake2b, cipherbird_vault_*, …)
//
// The executable demo target (`CipherBirdDemo`) is macOS-only by design:
// the XCFramework makes the bridge reusable on iOS, but the SwiftUI demo
// app itself is macOS-specific (NavigationSplitView, NSOpenPanel). iOS
// consumers depend on the library target and write their own UI.
import PackageDescription

let package = Package(
    name: "CipherBird",
    platforms: [
        .iOS(.v15),
        .macOS(.v14),
    ],
    products: [
        // Re-export the XCFramework's CipherBirdC module so downstream
        // packages can just `.product(name: "CipherBirdC", package: "CipherBird")`
        .library(name: "CipherBirdC", targets: ["CipherBirdC"]),
    ],
    targets: [
        // ─── The XCFramework, vendored as a binary target ───────────────────
        .binaryTarget(
            name: "CipherBirdC",
            path: "../../../CipherBird.xcframework"
        ),

        // ─── macOS-only SwiftUI demo executable ─────────────────────────────
        // Depends on the binary target directly — no separate Swift wrapper
        // target so we don't have to make every type `public`. iOS apps can
        // link the binary target alone and write their own UI.
        .executableTarget(
            name: "CipherBirdDemo",
            dependencies: ["CipherBirdC"],
            path: "Sources/CipherBirdDemo"
        ),
    ]
)
