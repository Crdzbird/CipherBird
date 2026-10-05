part of '../cipher_bird.dart';

final class _NativeEntropy {
  _NativeEntropy(DynamicLibrary lib)
    : entropyFromFile = lib
          .lookupFunction<_EntropyFromFileC, _EntropyFromFileDart>(
            'cryptolib_entropy_from_file',
          ),
      entropyFromFileDet = lib
          .lookupFunction<_EntropyFromFileC, _EntropyFromFileDart>(
            'cryptolib_entropy_from_file_deterministic',
          ),
      entropyFromFiles = lib
          .lookupFunction<_EntropyFromFilesC, _EntropyFromFilesDart>(
            'cryptolib_entropy_from_files',
          ),
      entropyFromFilesDet = lib
          .lookupFunction<_EntropyFromFilesC, _EntropyFromFilesDart>(
            'cryptolib_entropy_from_files_deterministic',
          ),
      entropyDeriveAll = lib
          .lookupFunction<_EntropyDeriveAllC, _EntropyDeriveAllDart>(
            'cryptolib_entropy_derive_all',
          ),
      entropySymKey = lib.lookupFunction<_EntropySymKeyC, _EntropySymKeyDart>(
        'cryptolib_entropy_symmetric_key',
      ),
      entropyRaw = lib.lookupFunction<_EntropyRawC, _EntropyRawDart>(
        'cryptolib_entropy_raw',
      ),
      entropyBoost = lib.lookupFunction<_EntropyBoostC, _EntropyBoostDart>(
        'cryptolib_entropy_boost',
      ),
      entropyInfo = lib.lookupFunction<_EntropyInfoC, _EntropyInfoDart>(
        'cryptolib_entropy_info',
      ),
      entropyAsymBundle = lib
          .lookupFunction<_EntropyAsymBundleC, _EntropyAsymBundleDart>(
            'cryptolib_entropy_asym_bundle',
          ),
      entropyRefresh = lib
          .lookupFunction<_EntropyRefreshC, _EntropyRefreshDart>(
            'cryptolib_entropy_refresh',
          ),
      entropyFree = lib.lookupFunction<_EntropyFreeC, _EntropyFreeDart>(
        'cryptolib_entropy_free',
      ),
      keyFromFile = lib.lookupFunction<_KeyFromFileC, _KeyFromFileDart>(
        'cryptolib_key_from_file',
      ),
      sealFromFile = lib.lookupFunction<_SealFromFileC, _SealFromFileDart>(
        'cryptolib_seal_from_file',
      ),
      openFromFile = lib.lookupFunction<_OpenFromFileC, _OpenFromFileDart>(
        'cryptolib_open_from_file',
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
