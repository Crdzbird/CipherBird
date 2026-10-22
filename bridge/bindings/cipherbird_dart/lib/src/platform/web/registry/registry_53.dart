part of '../web_platform.dart';

final Map<String, Function> _registry53 = {
  'cryptolib_fips_hpke_p256_seal':
      (
        Pointer<NativeType> pkR,
        int pkRLen,
        Pointer<NativeType> info,
        int infoLen,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> pt,
        int ptLen,
        Pointer<NativeType> outEnc,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_hpke_p256_seal',
        [
          pkR.address.toJS,
          pkRLen.toJS,
          info.address.toJS,
          infoLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
          pt.address.toJS,
          ptLen.toJS,
          outEnc.address.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_fips_hpke_p256_open':
      (
        Pointer<NativeType> enc,
        int encLen,
        Pointer<NativeType> skR,
        int skRLen,
        Pointer<NativeType> pkR,
        int pkRLen,
        Pointer<NativeType> info,
        int infoLen,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> ct,
        int ctLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_fips_hpke_p256_open',
        [
          enc.address.toJS,
          encLen.toJS,
          skR.address.toJS,
          skRLen.toJS,
          pkR.address.toJS,
          pkRLen.toJS,
          info.address.toJS,
          infoLen.toJS,
          aad.address.toJS,
          aadLen.toJS,
          ct.address.toJS,
          ctLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_version': () =>
      Pointer<Utf8>._(WebEngine.current.callInt('_cbw_cryptolib_version', [])),
};
