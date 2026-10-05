part of '../../cryptolib.dart';

typedef _EntropyFromFileC =
    Pointer<Void> Function(Pointer<Utf8> path, Pointer<Pointer<Utf8>> outError);
typedef _EntropyFromFileDart =
    Pointer<Void> Function(Pointer<Utf8> path, Pointer<Pointer<Utf8>> outError);
typedef _EntropyFromFilesC =
    Pointer<Void> Function(
      Pointer<Pointer<Utf8>> paths,
      Size count,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _EntropyFromFilesDart =
    Pointer<Void> Function(
      Pointer<Pointer<Utf8>> paths,
      int count,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _EntropyDeriveAllC = CryptoDerivedKeys Function(Pointer<Void> h);
typedef _EntropyDeriveAllDart = CryptoDerivedKeys Function(Pointer<Void> h);
typedef _EntropySymKeyC = CryptoBufferResult Function(Pointer<Void> h);
typedef _EntropySymKeyDart = CryptoBufferResult Function(Pointer<Void> h);
typedef _EntropyRawC = CryptoBufferResult Function(Pointer<Void> h);
typedef _EntropyRawDart = CryptoBufferResult Function(Pointer<Void> h);
typedef _EntropyBoostC = CryptoBufferResult Function(Pointer<Void> h);
typedef _EntropyBoostDart = CryptoBufferResult Function(Pointer<Void> h);
typedef _EntropyInfoC = CryptoEntropyInfo Function(Pointer<Void> h);
typedef _EntropyInfoDart = CryptoEntropyInfo Function(Pointer<Void> h);
typedef _EntropyAsymBundleC =
    CryptoAsymBundle Function(Pointer<Void> h, Pointer<Pointer<Utf8>> outError);
typedef _EntropyAsymBundleDart =
    CryptoAsymBundle Function(Pointer<Void> h, Pointer<Pointer<Utf8>> outError);
typedef _EntropyRefreshC = Void Function(Pointer<Void> h);
typedef _EntropyRefreshDart = void Function(Pointer<Void> h);
typedef _EntropyFreeC = Void Function(Pointer<Void> h);
typedef _EntropyFreeDart = void Function(Pointer<Void> h);
