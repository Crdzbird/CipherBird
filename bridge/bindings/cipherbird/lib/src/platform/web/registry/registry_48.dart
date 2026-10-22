part of '../web_platform.dart';

final Map<String, Function> _registry48 = {
  'cryptolib_session2_decrypt':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> msg,
        int msgLen,
        Pointer<NativeType> aad,
        int aadLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_session2_decrypt',
        [
          h.address.toJS,
          msg.address.toJS,
          msgLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_session2_free': (Pointer<NativeType> h) => WebEngine.current
      .callVoid('_cbw_cryptolib_session2_free', [h.address.toJS]),
  'cryptolib_fips_available': () =>
      WebEngine.current.callInt('_cbw_cryptolib_fips_available', []),
  'cryptolib_fips_init':
      (Pointer<NativeType> moduleDir, Pointer<NativeType> configFile) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_fips_init',
            [moduleDir.address.toJS, configFile.address.toJS],
            CipherBirdResult.size,
            CipherBirdResult._new,
          ),
  'cryptolib_fips_status': () => WebEngine.current.callStruct(
    '_cbw_cryptolib_fips_status',
    [],
    CipherBirdFipsStatus.size,
    CipherBirdFipsStatus._new,
  ),
  'cryptolib_fips_status_free': (Pointer<NativeType> s) => WebEngine.current
      .callVoid('_cbw_cryptolib_fips_status_free', [s.address.toJS]),
  'cryptolib_fips_digest': (int hash, Pointer<NativeType> data, int len) =>
      WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_digest',
        [hash.toJS, data.address.toJS, len.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fips_hmac':
      (
        int hash,
        Pointer<NativeType> key,
        int keyLen,
        Pointer<NativeType> data,
        int len,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_hmac',
        [hash.toJS, key.address.toJS, keyLen.toJS, data.address.toJS, len.toJS],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fips_hmac_verify':
      (
        int hash,
        Pointer<NativeType> key,
        int keyLen,
        Pointer<NativeType> data,
        int len,
        Pointer<NativeType> tag,
        int tagLen,
      ) => WebEngine.current.callInt('_cbw_cryptolib_fips_hmac_verify', [
        hash.toJS,
        key.address.toJS,
        keyLen.toJS,
        data.address.toJS,
        len.toJS,
        tag.address.toJS,
        tagLen.toJS,
      ]),
};
