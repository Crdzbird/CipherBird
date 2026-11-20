part of '../cipher_bird.dart';

final class _NativeCore {
  _NativeCore(DynamicLibrary lib)
    : init = lib.lookupFunction<_InitC, _InitDart>('cipherbird_init'),
      version = lib.lookupFunction<_VersionC, _VersionDart>(
        'cipherbird_version',
      ),
      randomBytes = lib.lookupFunction<_RandomBytesC, _RandomBytesDart>(
        'cipherbird_random_bytes',
      ),
      secureEqual = lib.lookupFunction<_SecureEqualC, _SecureEqualDart>(
        'cipherbird_secure_equal',
      ),
      bufferFree = lib.lookupFunction<_BufferFreeC, _BufferFreeDart>(
        'cipherbird_buffer_free',
      ),
      strFree = lib.lookupFunction<_StrFreeC, _StrFreeDart>(
        'cipherbird_str_free',
      );

  final _InitDart init;
  final _VersionDart version;
  final _RandomBytesDart randomBytes;
  final _SecureEqualDart secureEqual;
  final _BufferFreeDart bufferFree;
  final _StrFreeDart strFree;
}
