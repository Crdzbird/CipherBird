package cryptolib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"
)

// p256ConcurrentPEM is a fresh PKCS#8 PEM key written by crypto/x509 and the
// key itself, for checking cryptolib's signatures with crypto/ecdsa.
func p256ConcurrentPEM(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// p256ConcurrentRound runs every P-256 entry point once: the import of the
// PEM key, a signature that both cryptolib and crypto/ecdsa accept, the
// public key, and a fresh key pair that signs and verifies.
func p256ConcurrentRound(key *ecdsa.PrivateKey, keyPEM, message []byte) error {
	kp, err := P256PrivateKeyFromPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}
	sig, err := P256Sign(kp.Secret, message)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if !P256Verify(kp.Public, message, sig) {
		return errors.New("cryptolib rejects its own signature")
	}
	digest := sha256.Sum256(message)
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		return errors.New("crypto/ecdsa rejects the signature")
	}
	pub, err := P256PublicKey(kp.Secret)
	if err != nil || string(pub) != string(kp.Public) {
		return fmt.Errorf("public key: %v", err)
	}
	fresh, err := P256GenerateKey()
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	freshSig, err := P256Sign(fresh.Secret, message)
	if err != nil || !P256Verify(fresh.Public, message, freshSig) {
		return fmt.Errorf("fresh key: %v", err)
	}
	return nil
}

// p256Hammer runs workers goroutines of rounds rounds each, released together,
// and fails if they do not all finish within a minute.
func p256Hammer(t *testing.T, workers, rounds int) {
	t.Helper()
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if !P256Available() {
		t.Skip("P-256 is not in this build")
	}
	key, keyPEM := p256ConcurrentPEM(t)
	start := make(chan struct{})
	errs := make(chan error, workers*rounds)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < rounds; i++ {
				message := []byte(fmt.Sprintf("header.claims.%d.%d", w, i))
				if err := p256ConcurrentRound(key, keyPEM, message); err != nil {
					errs <- err
				}
			}
		}(w)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	close(start)
	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatal("concurrent P-256 calls did not finish within a minute")
	}
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestP256ConcurrentManyGoroutines(t *testing.T) {
	t.Parallel()
	p256Hammer(t, 64, 20)
}

func TestP256ConcurrentParallelTestsA(t *testing.T) {
	t.Parallel()
	p256Hammer(t, 8, 25)
}

func TestP256ConcurrentParallelTestsB(t *testing.T) {
	t.Parallel()
	p256Hammer(t, 8, 25)
}

func TestP256ConcurrentSameKeySameSignature(t *testing.T) {
	t.Parallel()
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if !P256DeterministicNonces() {
		t.Skip("deterministic nonces are not in this build")
	}
	_, keyPEM := p256ConcurrentPEM(t)
	kp, err := P256PrivateKeyFromPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("same")
	want, err := P256Sign(kp.Secret, message)
	if err != nil {
		t.Fatal(err)
	}
	const workers, rounds = 32, 20
	differ := make(chan string, workers*rounds)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				got, err := P256Sign(kp.Secret, message)
				if err != nil || string(got) != string(want) {
					differ <- fmt.Sprintf("%x %v", got, err)
				}
			}
		}()
	}
	wg.Wait()
	close(differ)
	for d := range differ {
		t.Errorf("signature differs under concurrency: %s", d)
	}
}
