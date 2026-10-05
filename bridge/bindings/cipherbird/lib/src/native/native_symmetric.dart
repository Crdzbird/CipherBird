part of '../cryptolib.dart';

final class _NativeSymmetric {
  _NativeSymmetric(DynamicLibrary lib)
    : symKeygen = lib.lookupFunction<_SymKeygenC, _SymKeygenDart>(
        'cryptolib_sym_keygen',
      ),
      xchacha20Enc = lib.lookupFunction<_XChaCha20EncC, _XChaCha20EncDart>(
        'cryptolib_xchacha20_encrypt',
      ),
      xchacha20Dec = lib.lookupFunction<_XChaCha20DecC, _XChaCha20DecDart>(
        'cryptolib_xchacha20_decrypt',
      ),
      aes256gcmEnc = lib.lookupFunction<_Aes256GcmEncC, _Aes256GcmEncDart>(
        'cryptolib_aes256gcm_encrypt',
      ),
      aes256gcmDec = lib.lookupFunction<_Aes256GcmDecC, _Aes256GcmDecDart>(
        'cryptolib_aes256gcm_decrypt',
      ),
      aes256gcmAvailable = lib
          .lookupFunction<_Aes256GcmAvailableC, _Aes256GcmAvailableDart>(
            'cryptolib_aes256gcm_available',
          ),
      streamEncCreate = lib
          .lookupFunction<_StreamEncCreateC, _StreamEncCreateDart>(
            'cryptolib_stream_enc_create',
          ),
      streamEncHeader = lib
          .lookupFunction<_StreamEncHeaderC, _StreamEncHeaderDart>(
            'cryptolib_stream_enc_header',
          ),
      streamEncPush = lib.lookupFunction<_StreamEncPushC, _StreamEncPushDart>(
        'cryptolib_stream_enc_push',
      ),
      streamEncFree = lib.lookupFunction<_StreamEncFreeC, _StreamEncFreeDart>(
        'cryptolib_stream_enc_free',
      ),
      streamDecCreate = lib
          .lookupFunction<_StreamDecCreateC, _StreamDecCreateDart>(
            'cryptolib_stream_dec_create',
          ),
      streamDecPull = lib.lookupFunction<_StreamDecPullC, _StreamDecPullDart>(
        'cryptolib_stream_dec_pull',
      ),
      streamDecFree = lib.lookupFunction<_StreamDecFreeC, _StreamDecFreeDart>(
        'cryptolib_stream_dec_free',
      );

  final _SymKeygenDart symKeygen;
  final _XChaCha20EncDart xchacha20Enc;
  final _XChaCha20DecDart xchacha20Dec;
  final _Aes256GcmEncDart aes256gcmEnc;
  final _Aes256GcmDecDart aes256gcmDec;
  final _Aes256GcmAvailableDart aes256gcmAvailable;
  final _StreamEncCreateDart streamEncCreate;
  final _StreamEncHeaderDart streamEncHeader;
  final _StreamEncPushDart streamEncPush;
  final _StreamEncFreeDart streamEncFree;
  final _StreamDecCreateDart streamDecCreate;
  final _StreamDecPullDart streamDecPull;
  final _StreamDecFreeDart streamDecFree;
}
