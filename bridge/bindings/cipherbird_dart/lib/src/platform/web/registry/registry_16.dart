part of '../web_platform.dart';

final Map<String, Function> _registry16 = {
  'cryptolib_entropy_from_files_deterministic':
      (Pointer<NativeType> paths, int count, Pointer<NativeType> outError) =>
          Pointer<Void>._(
            WebEngine.current.callInt(
              '_cbw_cryptolib_entropy_from_files_deterministic',
              [paths.address.toJS, count.toJS, outError.address.toJS],
            ),
          ),
  'cryptolib_entropy_derive_all': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_entropy_derive_all',
        [h.address.toJS],
        CipherBirdDerivedKeys.size,
        CipherBirdDerivedKeys._new,
      ),
  'cryptolib_entropy_symmetric_key': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_entropy_symmetric_key',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_entropy_raw': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_entropy_raw',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_entropy_boost': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_entropy_boost',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_entropy_info': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_entropy_info',
        [h.address.toJS],
        CipherBirdEntropyInfo.size,
        CipherBirdEntropyInfo._new,
      ),
  'cryptolib_entropy_asym_bundle':
      (Pointer<NativeType> h, Pointer<NativeType> outError) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_entropy_asym_bundle',
            [h.address.toJS, outError.address.toJS],
            CipherBirdAsymBundle.size,
            CipherBirdAsymBundle._new,
          ),
  'cryptolib_entropy_refresh': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_entropy_refresh', [h.address.toJS]),
  'cryptolib_entropy_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_entropy_free', [h.address.toJS]),
  'cryptolib_key_from_file': (Pointer<NativeType> path) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_key_from_file',
        [path.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_seal_from_file':
      (
        Pointer<NativeType> path,
        Pointer<NativeType> plaintext,
        Pointer<NativeType> aad,
        Pointer<NativeType> outError,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_seal_from_file',
        [
          path.address.toJS,
          plaintext.address.toJS,
          aad.address.toJS,
          outError.address.toJS,
        ],
        CipherBirdPacket.size,
        CipherBirdPacket._new,
      ),
  'cryptolib_open_from_file':
      (
        Pointer<NativeType> path,
        Pointer<NativeType> packet,
        Pointer<NativeType> aad,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_open_from_file',
        [path.address.toJS, packet.address.toJS, aad.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
