part of '../web_platform.dart';

final Map<String, Function> _registry36 = {
  'cryptolib_opaque_registration_request':
      (Pointer<NativeType> password, int passwordLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_opaque_registration_request',
            [password.address.toJS, passwordLen.toJS],
            CipherBirdOprfBlind.size,
            CipherBirdOprfBlind._new,
          ),
  'cryptolib_opaque_registration_response':
      (
        Pointer<NativeType> request,
        int requestLen,
        Pointer<NativeType> serverPublicKey,
        int spkLen,
        Pointer<NativeType> credentialIdentifier,
        int ciLen,
        Pointer<NativeType> oprfSeed,
        int seedLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_opaque_registration_response',
        [
          request.address.toJS,
          requestLen.toJS,
          serverPublicKey.address.toJS,
          spkLen.toJS,
          credentialIdentifier.address.toJS,
          ciLen.toJS,
          oprfSeed.address.toJS,
          seedLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_opaque_finalize_request':
      (
        Pointer<NativeType> password,
        int passwordLen,
        Pointer<NativeType> blind,
        int blindLen,
        Pointer<NativeType> response,
        int responseLen,
        Pointer<NativeType> serverIdentity,
        int sidLen,
        Pointer<NativeType> clientIdentity,
        int cidLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_opaque_finalize_request',
        [
          password.address.toJS,
          passwordLen.toJS,
          blind.address.toJS,
          blindLen.toJS,
          response.address.toJS,
          responseLen.toJS,
          serverIdentity.address.toJS,
          sidLen.toJS,
          clientIdentity.address.toJS,
          cidLen.toJS,
        ],
        CipherBirdOpaqueRecord.size,
        CipherBirdOpaqueRecord._new,
      ),
  'cryptolib_opaque_client_init':
      (Pointer<NativeType> password, int passwordLen) =>
          WebEngine.current.callStruct(
            '_cbw_cryptolib_opaque_client_init',
            [password.address.toJS, passwordLen.toJS],
            CipherBirdOpaqueKe1.size,
            CipherBirdOpaqueKe1._new,
          ),
};
