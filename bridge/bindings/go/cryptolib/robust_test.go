package cryptolib

// Robustness / Go-FFI-hardening tests. Run with the race detector and the
// dynamic library on the loader path, e.g.:
//
//	DYLD_LIBRARY_PATH=../../../build/release go test -race ./cryptolib
//	LD_LIBRARY_PATH=../../../build/release  go test -race ./cryptolib
//
// These target Go-specific failure modes that ordinary functional tests miss:
// finalizer use-after-free, double-free on Close, data races on shared handles,
// and panics from empty/edge-case inputs crossing the C boundary.

import (
	"runtime"
	"sync"
	"testing"
)

func init() { _ = Init() }

// TestEmptyInputsNeverPanic feeds empty/edge slices to every boundary helper
// that previously indexed &x[0]. A robust binding returns a value or an error —
// it must never panic the whole process on attacker-controlled empty input.
func TestEmptyInputsNeverPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("empty input panicked (DoS): %v", r)
		}
	}()
	empty := []byte{}
	_ = func() (out [][]byte) {
		b, _ := SHA256(empty)
		out = append(out, b)
		b, _ = SHA512(empty)
		out = append(out, b)
		b, _ = Blake2b(empty, nil)
		out = append(out, b)
		b, _ = Blake3(empty, 0)
		out = append(out, b)
		b, _ = Keccak256(empty)
		out = append(out, b)
		b, _ = Ripemd160(empty)
		out = append(out, b)
		_, _ = HmacSHA256(empty, empty)
		_, _ = Secp256k1Sign(empty, empty)
		_, _ = Secp256k1Recover(empty, empty)
		_ = Secp256k1Verify(empty, empty, empty)
		_, _ = BlsAggregate([][]byte{})
		_ = BlsAggregateVerify(nil, nil, empty)
		_, _ = RandomBytes(-1) // negative length must error, not allocate huge
		return
	}()
}

// TestNegativeRandomBytes ensures a negative length is rejected rather than
// wrapping to a gigantic size_t in C.
func TestNegativeRandomBytes(t *testing.T) {
	if _, err := RandomBytes(-1); err == nil {
		t.Fatal("RandomBytes(-1) should error")
	}
	if b, err := RandomBytes(0); err != nil || len(b) != 0 {
		t.Fatalf("RandomBytes(0) = %v, %v", b, err)
	}
}

// TestConcurrentStatelessUse hammers the stateless surface from many goroutines
// under -race to surface any shared-state data race in the binding/runtime glue.
func TestConcurrentStatelessUse(t *testing.T) {
	const G, N = 16, 500
	var wg sync.WaitGroup
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			msg := []byte{seed, seed ^ 0xa5, seed + 1}
			for i := 0; i < N; i++ {
				if _, err := SHA256(msg); err != nil {
					t.Error(err)
					return
				}
				if _, err := Keccak256(msg); err != nil {
					t.Error(err)
					return
				}
				kp := Secp256k1Keygen()
				dg, _ := Keccak256(msg)
				sig, err := Secp256k1Sign(dg, kp.Secret)
				if err != nil {
					t.Error(err)
					return
				}
				if !Secp256k1Verify(dg, sig[:64], kp.Public) {
					t.Error("verify failed")
					return
				}
			}
		}(byte(g))
	}
	wg.Wait()
}

// TestHandleFinalizerUAF creates handles, USES them, drops the reference, and
// forces GC in a tight loop. Without runtime.KeepAlive the finalizer could free
// the handle mid-call (use-after-free); with it, every call is safe.
func TestHandleFinalizerUAF(t *testing.T) {
	key := make([]byte, 32)
	for round := 0; round < 200; round++ {
		v, err := NewVault(key, KdfInteractive)
		if err != nil {
			t.Fatal(err)
		}
		// Use the handle, then immediately make it collectible and force GC to
		// race the finalizer against in-flight C calls.
		pkt, err := v.Seal([]byte("secret"), "aad")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Open(pkt, "aad"); err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		runtime.GC()
	}
}

// TestConcurrentCloseAndFinalizer calls Close explicitly while the GC finalizer
// may also fire — a double-free here would abort the process. Close must be
// idempotent and must cancel the finalizer.
func TestConcurrentCloseAndFinalizer(t *testing.T) {
	var wg sync.WaitGroup
	for round := 0; round < 300; round++ {
		k := NewKeyring()
		k.AddDeviceSlot(make([]byte, 32))
		wg.Add(1)
		go func() {
			defer wg.Done()
			k.Close()
			k.Close() // explicit double-close must be a no-op, not a double-free
		}()
		runtime.GC() // may schedule the (now-cancelled) finalizer
	}
	wg.Wait()
	runtime.GC()
	runtime.GC()
}

// TestStreamHandleLifecycle exercises a stateful handle across many push/pull
// rounds with interleaved GC, then explicit Close.
func TestStreamHandleLifecycle(t *testing.T) {
	key := make([]byte, 32)
	enc := NewStreamEncryptor(key)
	if enc == nil {
		t.Fatal("encryptor nil")
	}
	hdr, err := enc.Header()
	if err != nil {
		t.Fatal(err)
	}
	dec := NewStreamDecryptor(key, hdr)
	if dec == nil {
		t.Fatal("decryptor nil")
	}
	for i := 0; i < 100; i++ {
		ct, err := enc.Push([]byte("chunk"), TagMessage)
		if err != nil {
			t.Fatal(err)
		}
		pt, _, err := dec.Pull(ct)
		if err != nil {
			t.Fatal(err)
		}
		if string(pt) != "chunk" {
			t.Fatalf("round-trip mismatch: %q", pt)
		}
		runtime.GC()
	}
	enc.Close()
	dec.Close()
	enc.Close() // idempotent
	dec.Close()
}
