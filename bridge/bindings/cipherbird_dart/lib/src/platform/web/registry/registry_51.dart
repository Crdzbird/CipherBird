part of '../web_platform.dart';

final Map<String, Function> _registry51 = {
  'cryptolib_fips_envelope_create': (Pointer<NativeType> outError) =>
      Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_fips_envelope_create', [
          outError.address.toJS,
        ]),
      ),
  'cryptolib_fips_envelope_deserialise':
      (Pointer<NativeType> blob, int blobLen, Pointer<NativeType> outError) =>
          Pointer<Void>._(
            WebEngine.current.callInt(
              '_cbw_cryptolib_fips_envelope_deserialise',
              [blob.address.toJS, blobLen.toJS, outError.address.toJS],
            ),
          ),
  'cryptolib_fips_envelope_add_passphrase_slot':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> passphrase,
        int len,
        int iterations,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_envelope_add_passphrase_slot',
        [h.address.toJS, passphrase.address.toJS, len.toJS, iterations.toJS],
        CipherBirdResult.size,
        CipherBirdResult._new,
      ),
  'cryptolib_fips_envelope_add_key_slot':
      (Pointer<NativeType> h, Pointer<NativeType> factor, int len) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_fips_envelope_add_key_slot',
            [h.address.toJS, factor.address.toJS, len.toJS],
            CipherBirdResult.size,
            CipherBirdResult._new,
          ),
  'cryptolib_fips_envelope_unlock_with_passphrase':
      (Pointer<NativeType> h, Pointer<NativeType> passphrase, int len) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_fips_envelope_unlock_with_passphrase',
            [h.address.toJS, passphrase.address.toJS, len.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_fips_envelope_unlock_with_key':
      (Pointer<NativeType> h, Pointer<NativeType> factor, int len) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_fips_envelope_unlock_with_key',
            [h.address.toJS, factor.address.toJS, len.toJS],
            CipherBirdBufferResult.size,
            CipherBirdBufferResult._new,
          ),
  'cryptolib_fips_envelope_remove_slot': (Pointer<NativeType> h, int index) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_envelope_remove_slot',
        [h.address.toJS, index.toJS],
        CipherBirdResult.size,
        CipherBirdResult._new,
      ),
  'cryptolib_fips_envelope_slot_count': (Pointer<NativeType> h) => WebEngine
      .current
      .callInt('_cbw_cryptolib_fips_envelope_slot_count', [h.address.toJS]),
  'cryptolib_fips_envelope_serialise': (Pointer<NativeType> h) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_envelope_serialise',
        [h.address.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fips_envelope_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_fips_envelope_free', [h.address.toJS]),
};
