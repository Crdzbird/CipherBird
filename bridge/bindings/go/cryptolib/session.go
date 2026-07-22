package cryptolib

/*
#include "cryptolib_c.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"runtime"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Session — post-quantum forward-secret ratchet (hybrid KEM Double Ratchet)
//
// A live, back-and-forth channel with forward secrecy AND post-compromise
// security, all post-quantum (the asymmetric ratchet is X25519+ML-KEM-768). Where
// Flagship/Fortress seal to a static recipient key, a Session self-heals: a
// one-time state leak stops compromising the channel once each side ratchets.
//
//	// Bob (responder)
//	pre := cryptolib.GenerateSessionPrekey()            // publish pre.Public
//	// Alice (initiator)
//	alice, _ := cryptolib.InitiateSession(pre.Public)
//	hs, _ := alice.Handshake()                          // send hs to Bob
//	msg, _ := alice.Encrypt([]byte("hi"), nil)
//	// Bob
//	bob, _ := cryptolib.AcceptSession(hs, pre.Public, pre.Secret)
//	pt, _ := bob.Decrypt(msg, nil)
// ═══════════════════════════════════════════════════════════════════════════════

// Session is a stateful ratchet channel. Not safe for concurrent use; Close when done.
type Session struct{ handle C.CryptoSession }

func wrapSession(h C.CryptoSession) *Session {
	s := &Session{handle: h}
	runtime.SetFinalizer(s, func(s *Session) { s.Close() })
	return s
}

// GenerateSessionPrekey generates a responder prekey (a hybrid-KEM keypair).
// Publish Public; keep the pair to AcceptSession an incoming handshake.
func GenerateSessionPrekey() KeyPair {
	kp := C.cryptolib_session_generate_prekey()
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// InitiateSession (initiator) starts a session to responderPrekeyPublic. Call
// Handshake() on the returned session for the message to send to the responder.
func InitiateSession(responderPrekeyPublic []byte) (*Session, error) {
	var cerr *C.char
	h := C.cryptolib_session_initiate(u8(responderPrekeyPublic), C.size_t(len(responderPrekeyPublic)), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	if h == nil {
		return nil, errors.New("cryptolib: session initiate failed")
	}
	return wrapSession(h), nil
}

// Handshake returns the message an initiator must send to the responder
// (AcceptSession). Empty on a responder session.
func (s *Session) Handshake() ([]byte, error) {
	defer runtime.KeepAlive(s)
	return checkBufResult(C.cryptolib_session_handshake(s.handle))
}

// AcceptSession (responder) accepts an incoming handshake with your prekey pair.
func AcceptSession(handshake, prekeyPublic, prekeySecret []byte) (*Session, error) {
	var cerr *C.char
	h := C.cryptolib_session_accept(u8(handshake), C.size_t(len(handshake)),
		u8(prekeyPublic), C.size_t(len(prekeyPublic)), u8(prekeySecret), C.size_t(len(prekeySecret)), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	if h == nil {
		return nil, errors.New("cryptolib: session accept failed")
	}
	return wrapSession(h), nil
}

// Encrypt the next outgoing message (advances the sending ratchet). aad may be nil.
func (s *Session) Encrypt(plaintext, aad []byte) ([]byte, error) {
	defer runtime.KeepAlive(s)
	return checkBufResult(C.cryptolib_session_encrypt(s.handle,
		u8(plaintext), C.size_t(len(plaintext)), u8(aad), C.size_t(len(aad))))
}

// Decrypt an incoming message. Handles ratchet turns + out-of-order delivery, and
// is transactional: a rejected message leaves the session usable.
func (s *Session) Decrypt(message, aad []byte) ([]byte, error) {
	defer runtime.KeepAlive(s)
	return checkBufResult(C.cryptolib_session_decrypt(s.handle,
		u8(message), C.size_t(len(message)), u8(aad), C.size_t(len(aad))))
}

// Close frees the native session. Safe to call more than once.
func (s *Session) Close() {
	if s.handle != nil {
		C.cryptolib_session_free(s.handle)
		s.handle = nil
	}
}
