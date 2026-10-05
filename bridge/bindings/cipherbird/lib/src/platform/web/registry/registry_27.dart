part of '../web_platform.dart';

final Map<String, Function> _registry27 = {
  'cryptolib_hpke_setup_r':
      (
        int kdf,
        int aead,
        int mode,
        Pointer<NativeType> enc,
        int encLen,
        Pointer<NativeType> skR,
        int skRLen,
        Pointer<NativeType> info,
        int infoLen,
        Pointer<NativeType> psk,
        int pskLen,
        Pointer<NativeType> pskId,
        int pskIdLen,
        Pointer<NativeType> pkS,
        int pkSLen,
        Pointer<NativeType> outError,
      ) => Pointer<Void>._(
        WebEngine.current.callInt('_cbw_cryptolib_hpke_setup_r', [
          kdf.toJS,
          aead.toJS,
          mode.toJS,
          enc.address.toJS,
          encLen.toJS,
          skR.address.toJS,
          skRLen.toJS,
          info.address.toJS,
          infoLen.toJS,
          psk.address.toJS,
          pskLen.toJS,
          pskId.address.toJS,
          pskIdLen.toJS,
          pkS.address.toJS,
          pkSLen.toJS,
          outError.address.toJS,
        ]),
      ),
  'cryptolib_hpke_seal':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> pt,
        int ptLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hpke_seal',
        [
          h.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
          pt.address.toJS,
          ptLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_hpke_open':
      (
        Pointer<NativeType> h,
        Pointer<NativeType> aad,
        int aadLen,
        Pointer<NativeType> ct,
        int ctLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_hpke_open',
        [
          h.address.toJS,
          aad.address.toJS,
          aadLen.toJS,
          ct.address.toJS,
          ctLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
};
