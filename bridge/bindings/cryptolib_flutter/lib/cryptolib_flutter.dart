/// CryptoLib for Flutter — public API.
///
/// `CryptoLib` is the entry point. The native library loads lazily on first use;
/// call `CryptoLib.preload()` once at app start to warm it off the UI isolate.
///
/// The crypto operations live on domain extensions of `CryptoLib` (hashing,
/// symmetric, asymmetric, vault, keyring, post-quantum, BLS, asymmetric vault,
/// media entropy, steganography) — all are re-exported here, so a single
/// `import 'package:cryptolib_flutter/cryptolib_flutter.dart';` brings the full
/// surface into scope. The raw FFI structs/typedefs stay internal.
library;

export 'src/cryptolib.dart'
    show
        AsymBundleResult,
        CryptoLib,
        CryptoLibAsymmetric,
        CryptoLibAsymmetricVault,
        CryptoLibBls,
        CryptoLibCore,
        CryptoLibEntropy,
        CryptoLibEvmBtc,
        CryptoLibHashing,
        CryptoLibKeyring,
        CryptoLibMolecular,
        CryptoLibPostQuantum,
        CryptoLibStego,
        CryptoLibSuite,
        CryptoLibSymmetric,
        CryptoLibVault,
        DerivedKeysResult,
        EntropyInfoResult,
        KeyPairResult,
        Packet;
