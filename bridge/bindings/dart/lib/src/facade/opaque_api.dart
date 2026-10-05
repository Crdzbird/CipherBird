part of '../../cryptolib_ffi.dart';

/// OPAQUE password-authenticated key exchange.
extension type OpaqueApi(CryptoLib _l) {
  /// Client registration step 1: blind the password -> {blind, request}.
  OprfBlindResult registrationRequest(Uint8List password) =>
      _l.opaqueRegistrationRequest(password);

  /// Server registration step: -> 64-byte registration response.
  Uint8List registrationResponse(Uint8List request, Uint8List serverPublicKey,
          Uint8List credentialIdentifier, Uint8List oprfSeed) =>
      _l.opaqueRegistrationResponse(
          request, serverPublicKey, credentialIdentifier, oprfSeed);

  /// Client registration step 2: -> {record, exportKey}.
  OpaqueRecord finalizeRequest(
          Uint8List password, Uint8List blind, Uint8List response,
          {Uint8List? serverIdentity, Uint8List? clientIdentity}) =>
      _l.opaqueFinalizeRequest(password, blind, response,
          serverIdentity: serverIdentity, clientIdentity: clientIdentity);

  /// Client login step 1: -> {ke1, clientState}.
  OpaqueKe1 clientInit(Uint8List password) => _l.opaqueClientInit(password);

  /// Server login step 1: -> {ke2, serverState}.
  OpaqueKe2 serverRespond(
          Uint8List context,
          Uint8List serverPrivateKey,
          Uint8List serverPublicKey,
          Uint8List record,
          Uint8List credentialIdentifier,
          Uint8List oprfSeed,
          Uint8List ke1,
          {Uint8List? serverIdentity,
          Uint8List? clientIdentity}) =>
      _l.opaqueServerRespond(context, serverPrivateKey, serverPublicKey, record,
          credentialIdentifier, oprfSeed, ke1,
          serverIdentity: serverIdentity, clientIdentity: clientIdentity);

  /// Client login step 2: authenticate server -> {ke3, sessionKey, exportKey}.
  /// Throws on a wrong password / server authentication failure.
  OpaqueKe3 clientFinish(
          Uint8List clientState, Uint8List ke2, Uint8List context,
          {Uint8List? serverIdentity, Uint8List? clientIdentity}) =>
      _l.opaqueClientFinish(clientState, ke2, context,
          serverIdentity: serverIdentity, clientIdentity: clientIdentity);

  /// Server login step 2: verify KE3 -> the session key (throws on failure).
  Uint8List serverFinish(Uint8List serverState, Uint8List ke3) =>
      _l.opaqueServerFinish(serverState, ke3);
}
