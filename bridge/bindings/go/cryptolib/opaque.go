package cryptolib

/*
#include "cryptolib_c.h"
#include <stdlib.h>
*/
import "C"

import "errors"

// ═══════════════════════════════════════════════════════════════════════════════
// OPAQUE — asymmetric PAKE (draft-irtf-cfrg-opaque, OPAQUE-3DH, ristretto255-SHA512)
//
// A client and server agree on a session key from a password that never leaves
// the client and is never stored server-side. Two phases: registration, then a
// 3DH login with mutual authentication.
//
//	// Registration
//	rr, _ := cryptolib.OpaqueRegistrationRequest(password)                 // client
//	resp, _ := cryptolib.OpaqueRegistrationResponse(rr.Request, serverPub, credID, oprfSeed) // server
//	rec, _ := cryptolib.OpaqueFinalizeRequest(password, rr.Blind, resp, nil, nil)            // client → store rec.Record
//	// Login
//	ke1, _ := cryptolib.OpaqueClientInit(password)                         // client
//	ke2, _ := cryptolib.OpaqueServerRespond(ctx, serverPriv, serverPub, rec.Record, credID, oprfSeed, ke1.Ke1, nil, nil)
//	ke3, err := cryptolib.OpaqueClientFinish(ke1.ClientState, ke2.Ke2, ctx, nil, nil) // err ⇒ wrong password/server
//	sk, _ := cryptolib.OpaqueServerFinish(ke2.ServerState, ke3.Ke3)        // sk == ke3.SessionKey
// ═══════════════════════════════════════════════════════════════════════════════

// OpaqueRegistrationRequest output: the secret blind + the request to send.
type OpaqueRegistrationRequestResult struct {
	Blind   []byte
	Request []byte
}

// OpaqueRecord is the client's registration record + export key.
type OpaqueRecord struct {
	Record    []byte
	ExportKey []byte
}

// OpaqueKe1 is the client's login message 1 + opaque client state.
type OpaqueKe1 struct {
	Ke1         []byte
	ClientState []byte
}

// OpaqueKe2 is the server's login message 2 + opaque server state.
type OpaqueKe2 struct {
	Ke2         []byte
	ServerState []byte
}

// OpaqueKe3 is the client's login message 3 + the session key + export key.
type OpaqueKe3 struct {
	Ke3        []byte
	SessionKey []byte
	ExportKey  []byte
}

// OpaqueRegistrationRequest (client) blinds the password.
func OpaqueRegistrationRequest(password []byte) (OpaqueRegistrationRequestResult, error) {
	b := C.cryptolib_opaque_registration_request(u8(password), C.size_t(len(password)))
	if b.error != nil {
		msg := C.GoString(b.error)
		C.cryptolib_oprf_blind_free(&b)
		return OpaqueRegistrationRequestResult{}, errors.New(msg)
	}
	defer C.cryptolib_oprf_blind_free(&b)
	return OpaqueRegistrationRequestResult{Blind: cbufBytes(b.blind), Request: cbufBytes(b.blinded_element)}, nil
}

// OpaqueRegistrationResponse (server) evaluates the request → 64-byte response.
func OpaqueRegistrationResponse(request, serverPublicKey, credentialIdentifier, oprfSeed []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_opaque_registration_response(
		u8(request), C.size_t(len(request)), u8(serverPublicKey), C.size_t(len(serverPublicKey)),
		u8(credentialIdentifier), C.size_t(len(credentialIdentifier)), u8(oprfSeed), C.size_t(len(oprfSeed))))
}

// OpaqueFinalizeRequest (client) → record (store on server) + export key.
func OpaqueFinalizeRequest(password, blind, response, serverIdentity, clientIdentity []byte) (OpaqueRecord, error) {
	r := C.cryptolib_opaque_finalize_request(u8(password), C.size_t(len(password)),
		u8(blind), C.size_t(len(blind)), u8(response), C.size_t(len(response)),
		u8(serverIdentity), C.size_t(len(serverIdentity)), u8(clientIdentity), C.size_t(len(clientIdentity)))
	if r.error != nil {
		msg := C.GoString(r.error)
		C.cryptolib_opaque_record_free(&r)
		return OpaqueRecord{}, errors.New(msg)
	}
	defer C.cryptolib_opaque_record_free(&r)
	return OpaqueRecord{Record: cbufBytes(r.record), ExportKey: cbufBytes(r.export_key)}, nil
}

// OpaqueClientInit (client) → KE1 + client state.
func OpaqueClientInit(password []byte) (OpaqueKe1, error) {
	k := C.cryptolib_opaque_client_init(u8(password), C.size_t(len(password)))
	if k.error != nil {
		msg := C.GoString(k.error)
		C.cryptolib_opaque_ke1_free(&k)
		return OpaqueKe1{}, errors.New(msg)
	}
	defer C.cryptolib_opaque_ke1_free(&k)
	return OpaqueKe1{Ke1: cbufBytes(k.ke1), ClientState: cbufBytes(k.client_state)}, nil
}

// OpaqueServerRespond (server) → KE2 + server state.
func OpaqueServerRespond(context, serverPrivateKey, serverPublicKey, record, credentialIdentifier, oprfSeed, ke1, serverIdentity, clientIdentity []byte) (OpaqueKe2, error) {
	k := C.cryptolib_opaque_server_respond(u8(context), C.size_t(len(context)),
		u8(serverPrivateKey), C.size_t(len(serverPrivateKey)), u8(serverPublicKey), C.size_t(len(serverPublicKey)),
		u8(record), C.size_t(len(record)), u8(credentialIdentifier), C.size_t(len(credentialIdentifier)),
		u8(oprfSeed), C.size_t(len(oprfSeed)), u8(ke1), C.size_t(len(ke1)),
		u8(serverIdentity), C.size_t(len(serverIdentity)), u8(clientIdentity), C.size_t(len(clientIdentity)))
	if k.error != nil {
		msg := C.GoString(k.error)
		C.cryptolib_opaque_ke2_free(&k)
		return OpaqueKe2{}, errors.New(msg)
	}
	defer C.cryptolib_opaque_ke2_free(&k)
	return OpaqueKe2{Ke2: cbufBytes(k.ke2), ServerState: cbufBytes(k.server_state)}, nil
}

// OpaqueClientFinish (client) authenticates the server → KE3 + session key +
// export key. A non-nil error means a wrong password or server authentication
// failure.
func OpaqueClientFinish(clientState, ke2, context, serverIdentity, clientIdentity []byte) (OpaqueKe3, error) {
	k := C.cryptolib_opaque_client_finish(u8(clientState), C.size_t(len(clientState)),
		u8(ke2), C.size_t(len(ke2)), u8(context), C.size_t(len(context)),
		u8(serverIdentity), C.size_t(len(serverIdentity)), u8(clientIdentity), C.size_t(len(clientIdentity)))
	if k.error != nil {
		msg := C.GoString(k.error)
		C.cryptolib_opaque_ke3_free(&k)
		return OpaqueKe3{}, errors.New(msg)
	}
	defer C.cryptolib_opaque_ke3_free(&k)
	return OpaqueKe3{Ke3: cbufBytes(k.ke3), SessionKey: cbufBytes(k.session_key), ExportKey: cbufBytes(k.export_key)}, nil
}

// OpaqueServerFinish (server) verifies KE3 → the session key (error on failure).
func OpaqueServerFinish(serverState, ke3 []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_opaque_server_finish(
		u8(serverState), C.size_t(len(serverState)), u8(ke3), C.size_t(len(ke3))))
}
