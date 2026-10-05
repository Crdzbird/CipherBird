part of '../../cipher_bird.dart';

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
typedef _EntropyDeriveAllC = CipherBirdDerivedKeys Function(Pointer<Void> h);
typedef _EntropyDeriveAllDart = CipherBirdDerivedKeys Function(Pointer<Void> h);
typedef _EntropySymKeyC = CipherBirdBufferResult Function(Pointer<Void> h);
typedef _EntropySymKeyDart = CipherBirdBufferResult Function(Pointer<Void> h);
typedef _EntropyRawC = CipherBirdBufferResult Function(Pointer<Void> h);
typedef _EntropyRawDart = CipherBirdBufferResult Function(Pointer<Void> h);
typedef _EntropyBoostC = CipherBirdBufferResult Function(Pointer<Void> h);
typedef _EntropyBoostDart = CipherBirdBufferResult Function(Pointer<Void> h);
typedef _EntropyInfoC = CipherBirdEntropyInfo Function(Pointer<Void> h);
typedef _EntropyInfoDart = CipherBirdEntropyInfo Function(Pointer<Void> h);
typedef _EntropyAsymBundleC =
    CipherBirdAsymBundle Function(
      Pointer<Void> h,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _EntropyAsymBundleDart =
    CipherBirdAsymBundle Function(
      Pointer<Void> h,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _EntropyRefreshC = Void Function(Pointer<Void> h);
typedef _EntropyRefreshDart = void Function(Pointer<Void> h);
typedef _EntropyFreeC = Void Function(Pointer<Void> h);
typedef _EntropyFreeDart = void Function(Pointer<Void> h);
