package cryptolib

import (
	"bytes"
	"testing"
)

func TestOpaqueEndToEnd(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	password := []byte("hunter2")
	oprfSeed, _ := RandomBytes(64)
	dseed, _ := RandomBytes(32)
	server, err := OprfDeriveKeyPair(dseed, nil) // a valid ristretto255 DH keypair
	if err != nil {
		t.Fatal(err)
	}
	credID := []byte("id")
	ctx := []byte("app")

	// Registration.
	rr, err := OpaqueRegistrationRequest(password)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := OpaqueRegistrationResponse(rr.Request, server.Public, credID, oprfSeed)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := OpaqueFinalizeRequest(password, rr.Blind, resp, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Record) != 192 || len(rec.ExportKey) != 64 {
		t.Fatalf("bad record/export sizes: %d %d", len(rec.Record), len(rec.ExportKey))
	}

	// Login (correct password).
	ke1, err := OpaqueClientInit(password)
	if err != nil {
		t.Fatal(err)
	}
	ke2, err := OpaqueServerRespond(ctx, server.Secret, server.Public, rec.Record, credID, oprfSeed, ke1.Ke1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ke3, err := OpaqueClientFinish(ke1.ClientState, ke2.Ke2, ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := OpaqueServerFinish(ke2.ServerState, ke3.Ke3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk, ke3.SessionKey) {
		t.Fatal("session keys differ between client and server")
	}
	if !bytes.Equal(ke3.ExportKey, rec.ExportKey) {
		t.Fatal("export key differs from registration")
	}

	// Login (wrong password) → client cannot authenticate.
	ke1b, _ := OpaqueClientInit([]byte("wrongpw"))
	ke2b, _ := OpaqueServerRespond(ctx, server.Secret, server.Public, rec.Record, credID, oprfSeed, ke1b.Ke1, nil, nil)
	if _, err := OpaqueClientFinish(ke1b.ClientState, ke2b.Ke2, ctx, nil, nil); err == nil {
		t.Fatal("wrong password was accepted")
	}
}
