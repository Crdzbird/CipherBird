part of '../cipher_bird.dart';

final class _NativeEntropy {
  _NativeEntropy(DynamicLibrary lib)
    : entropyFromFile = lib
          .lookupFunction<_EntropyFromFileC, _EntropyFromFileDart>(
            'cipherbird_entropy_from_file',
          ),
      entropyFromFileDet = lib
          .lookupFunction<_EntropyFromFileC, _EntropyFromFileDart>(
            'cipherbird_entropy_from_file_deterministic',
          ),
      entropyFromFiles = lib
          .lookupFunction<_EntropyFromFilesC, _EntropyFromFilesDart>(
            'cipherbird_entropy_from_files',
          ),
      entropyFromFilesDet = lib
          .lookupFunction<_EntropyFromFilesC, _EntropyFromFilesDart>(
            'cipherbird_entropy_from_files_deterministic',
          ),
      entropyDeriveAll = lib
          .lookupFunction<_EntropyDeriveAllC, _EntropyDeriveAllDart>(
            'cipherbird_entropy_derive_all',
          ),
      entropySymKey = lib.lookupFunction<_EntropySymKeyC, _EntropySymKeyDart>(
        'cipherbird_entropy_symmetric_key',
      ),
      entropyRaw = lib.lookupFunction<_EntropyRawC, _EntropyRawDart>(
        'cipherbird_entropy_raw',
      ),
      entropyBoost = lib.lookupFunction<_EntropyBoostC, _EntropyBoostDart>(
        'cipherbird_entropy_boost',
      ),
      entropyInfo = lib.lookupFunction<_EntropyInfoC, _EntropyInfoDart>(
        'cipherbird_entropy_info',
      ),
      entropyAsymBundle = lib
          .lookupFunction<_EntropyAsymBundleC, _EntropyAsymBundleDart>(
            'cipherbird_entropy_asym_bundle',
          ),
      entropyRefresh = lib
          .lookupFunction<_EntropyRefreshC, _EntropyRefreshDart>(
            'cipherbird_entropy_refresh',
          ),
      entropyFree = lib.lookupFunction<_EntropyFreeC, _EntropyFreeDart>(
        'cipherbird_entropy_free',
      ),
      keyFromFile = lib.lookupFunction<_KeyFromFileC, _KeyFromFileDart>(
        'cipherbird_key_from_file',
      ),
      sealFromFile = lib.lookupFunction<_SealFromFileC, _SealFromFileDart>(
        'cipherbird_seal_from_file',
      ),
      openFromFile = lib.lookupFunction<_OpenFromFileC, _OpenFromFileDart>(
        'cipherbird_open_from_file',
      );

  final _EntropyFromFileDart entropyFromFile;
  final _EntropyFromFileDart entropyFromFileDet;
  final _EntropyFromFilesDart entropyFromFiles;
  final _EntropyFromFilesDart entropyFromFilesDet;
  final _EntropyDeriveAllDart entropyDeriveAll;
  final _EntropySymKeyDart entropySymKey;
  final _EntropyRawDart entropyRaw;
  final _EntropyBoostDart entropyBoost;
  final _EntropyInfoDart entropyInfo;
  final _EntropyAsymBundleDart entropyAsymBundle;
  final _EntropyRefreshDart entropyRefresh;
  final _EntropyFreeDart entropyFree;
  final _KeyFromFileDart keyFromFile;
  final _SealFromFileDart sealFromFile;
  final _OpenFromFileDart openFromFile;
}
