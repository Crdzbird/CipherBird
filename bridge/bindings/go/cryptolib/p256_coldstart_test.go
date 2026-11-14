//go:build unix

package cryptolib

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// p256ColdChildEnv marks the child process of TestP256ColdStartUnderSignals.
const p256ColdChildEnv = "CRYPTOLIB_P256_COLD_CHILD"

// TestP256ColdStartUnderSignals reproduces the hang a Go server hit: the
// first P-256 calls of a process, made by several goroutines together while
// signals keep reaching the threads that run them. Here the signals are the
// CPU profiler's SIGPROF and SIGURG, the runtime's own preemption signal,
// sent to the process in a loop. Without the fix every goroutine stayed in
// cryptolib_p256_sign, blocked in libcrypto on a pthread rwlock that no
// thread held. libcrypto must be cold, so the test runs this test binary
// again as a child that does only that, and fails if the child does not
// finish.
func TestP256ColdStartUnderSignals(t *testing.T) {
	if os.Getenv(p256ColdChildEnv) == "1" {
		p256ColdChild(t)
		return
	}
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if !P256Available() {
		t.Skip("P-256 is not in this build")
	}
	for round := 0; round < 4; round++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestP256ColdStartUnderSignals$", "-test.count=1")
		cmd.Env = append(os.Environ(), p256ColdChildEnv+"=1")
		out, err := cmd.CombinedOutput()
		expired := ctx.Err() != nil
		cancel()
		if expired {
			t.Fatalf("round %d: the cold child did not finish within a minute\n%s", round, out)
		}
		if err != nil {
			t.Fatalf("round %d: the cold child failed: %v\n%s", round, err, out)
		}
	}
}

// p256ColdChild is the child's whole run. The package's init has called
// Init, as every user of the binding does, and nothing else has touched
// libcrypto yet. The test goroutine signals the process until the workers
// are done or half a second has passed, then gives them 20 seconds more.
func p256ColdChild(t *testing.T) {
	runtime.SetCPUProfileRate(5000)
	defer runtime.SetCPUProfileRate(0)
	key, keyPEM := p256ConcurrentPEM(t)
	const workers = 8
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			if err := p256ConcurrentRound(key, keyPEM, []byte(fmt.Sprintf("cold.%d", w))); err != nil {
				errs <- err
			}
		}(w)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	pid := os.Getpid()
	close(start)
	stop := time.Now().Add(500 * time.Millisecond)
	for signalling := true; signalling && time.Now().Before(stop); {
		select {
		case <-done:
			signalling = false
		default:
			_ = syscall.Kill(pid, syscall.SIGURG)
			runtime.Gosched()
		}
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the first concurrent P-256 calls did not finish within 20 seconds of the signals")
	}
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
