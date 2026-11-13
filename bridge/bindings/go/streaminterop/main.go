// Cross-language SecretStream interop: write a chunked stream to a file, or
// read one and report what it held. The Dart program
// bridge/bindings/cipherbird_dart/bin/stream_interop.dart speaks the same
// file layout, and scripts/verify_stream_interop.sh runs each against the
// other.
//
//	go run ./streaminterop write <file> <chunks>
//	go run ./streaminterop read <file>
//
// File layout: the 24-byte stream header, then for every chunk a 4-byte
// big-endian ciphertext length and the ciphertext. Plaintext chunk i is
// 64 KiB of (i*31 + j*7) mod 256; the last chunk is half that size and
// carries the final tag. Both commands print
//
//	digest <hex> chunks <n> final <true|false>
//
// where digest starts as 32 zero bytes and becomes
// SHA-256(digest || SHA-256(chunk)) for every plaintext chunk in order.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Crdzbird/CipherBird/bridge/bindings/go/cryptolib"
)

const (
	keyHex    = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	chunkSize = 64 * 1024
)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}

func chunkOf(index, size int) []byte {
	out := make([]byte, size)
	for j := range out {
		out[j] = byte(index*31 + j*7)
	}
	return out
}

func mix(digest, chunk []byte) []byte {
	inner, err := cryptolib.SHA256(chunk)
	if err != nil {
		fail("sha256: %v", err)
	}
	outer, err := cryptolib.SHA256(append(append([]byte(nil), digest...), inner...))
	if err != nil {
		fail("sha256: %v", err)
	}
	return outer
}

func write(path string, chunks int) {
	key, _ := hex.DecodeString(keyHex)
	enc := cryptolib.NewStreamEncryptor(key)
	if enc == nil {
		fail("encryptor")
	}
	defer enc.Close()
	header, err := enc.Header()
	if err != nil {
		fail("header: %v", err)
	}
	f, err := os.Create(path)
	if err != nil {
		fail("%v", err)
	}
	defer f.Close()
	if _, err := f.Write(header); err != nil {
		fail("%v", err)
	}
	digest := make([]byte, 32)
	for i := 0; i < chunks; i++ {
		size, tag := chunkSize, cryptolib.TagMessage
		if i == chunks-1 {
			size, tag = chunkSize/2, cryptolib.TagFinal
		}
		plain := chunkOf(i, size)
		ct, err := enc.Push(plain, tag)
		if err != nil {
			fail("push %d: %v", i, err)
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(ct)))
		if _, err := f.Write(append(length[:], ct...)); err != nil {
			fail("%v", err)
		}
		digest = mix(digest, plain)
	}
	fmt.Printf("digest %s chunks %d final true\n", hex.EncodeToString(digest), chunks)
}

func read(path string) {
	key, _ := hex.DecodeString(keyHex)
	f, err := os.Open(path)
	if err != nil {
		fail("%v", err)
	}
	defer f.Close()
	header := make([]byte, 24)
	if _, err := io.ReadFull(f, header); err != nil {
		fail("header: %v", err)
	}
	dec := cryptolib.NewStreamDecryptor(key, header)
	if dec == nil {
		fail("decryptor")
	}
	defer dec.Close()
	digest := make([]byte, 32)
	chunks, final := 0, false
	for {
		var length [4]byte
		if _, err := io.ReadFull(f, length[:]); err == io.EOF {
			break
		} else if err != nil {
			fail("length: %v", err)
		}
		if final {
			fail("data after the final chunk")
		}
		ct := make([]byte, binary.BigEndian.Uint32(length[:]))
		if _, err := io.ReadFull(f, ct); err != nil {
			fail("chunk %d is cut short: %v", chunks, err)
		}
		plain, tag, err := dec.Pull(ct)
		if err != nil {
			fail("chunk %d rejected: %v", chunks, err)
		}
		digest = mix(digest, plain)
		chunks++
		final = tag == cryptolib.TagFinal
	}
	fmt.Printf("digest %s chunks %d final %v\n", hex.EncodeToString(digest), chunks, final)
}

func main() {
	if err := cryptolib.Init(); err != nil {
		fail("init: %v", err)
	}
	if len(os.Args) == 4 && os.Args[1] == "write" {
		n, err := strconv.Atoi(os.Args[3])
		if err != nil || n < 1 {
			fail("chunks must be a positive number")
		}
		write(os.Args[2], n)
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "read" {
		read(os.Args[2])
		return
	}
	fail("usage: streaminterop write <file> <chunks> | read <file>")
}
