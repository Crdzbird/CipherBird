// LavaRand CLI Client — interacts with the CryptoLib LavaRand HTTP server.
//
// The client and server use DIFFERENT files for DIFFERENT purposes:
//
//   Server file: LavaRand entropy source (any file — webcam, mic, lava lamp photo).
//                Mixed with system entropy. Different keys every call. Seeds the PRNG.
//
//   Client file: Your private identity file (your personal photo, voice memo, etc.).
//                Deterministic mode. Same file → same Ed25519 keypair every time.
//                The file IS your credential — like a hardware security key.
//
// The files do NOT need to match. The server never sees the client's file.
//
// Usage:
//
//	go run ./client/ [--server URL] <command> [args...]
//
// Commands:
//
//	status                                Show server entropy status
//	enroll <identity-file>                Enroll with file-derived Ed25519 pubkey
//	challenge <identity-file>             Get challenge, sign with file key, verify
//	encrypt <message>                     Encrypt a message (server uses LavaRand key)
//	decrypt <ciphertext_hex> <key_id>     Decrypt with server's ephemeral key
//	rotate                                Trigger server key rotation
//	demo <identity-file>                  Run full demo: enroll -> challenge -> encrypt -> decrypt
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Crdzbird/CipherBird/bridge/bindings/go/cryptolib"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

var serverURL = "http://localhost:8443"

func must[T any](v T, err error) T {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
	return v
}

func postJSON(path string, body any) map[string]any {
	data := must(json.Marshal(body))
	resp := must(http.Post(serverURL+path, "application/json", bytes.NewReader(data)))
	defer resp.Body.Close()
	raw := must(io.ReadAll(resp.Body))
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: invalid JSON from server: %s\n", string(raw))
		os.Exit(1)
	}
	return result
}

func getJSON(path string) map[string]any {
	resp := must(http.Get(serverURL + path))
	defer resp.Body.Close()
	raw := must(io.ReadAll(resp.Body))
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: invalid JSON from server: %s\n", string(raw))
		os.Exit(1)
	}
	return result
}

func printLabel(label, value string) {
	fmt.Printf("  %-22s %s\n", label+":", value)
}

func printResult(label string, ok bool) {
	mark := "\u2717"
	if ok {
		mark = "\u2713"
	}
	fmt.Printf("  %s %s\n", mark, label)
}

func prettyJSON(m map[string]any) {
	for k, v := range m {
		switch val := v.(type) {
		case float64:
			if val == float64(int64(val)) {
				printLabel(k, fmt.Sprintf("%d", int64(val)))
			} else {
				printLabel(k, fmt.Sprintf("%.2f", val))
			}
		case bool:
			printLabel(k, fmt.Sprintf("%v", val))
		default:
			printLabel(k, fmt.Sprintf("%v", val))
		}
	}
}

// deriveEd25519 derives a deterministic Ed25519 keypair from an entropy file.
func deriveEd25519(entropyFile string) cryptolib.KeyPair {
	ent := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
	defer ent.Close()
	keys := ent.DeriveAll()
	return cryptolib.Ed25519KeygenFromSeed(keys.SigningSeed)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Commands
// ═══════════════════════════════════════════════════════════════════════════════

func cmdStatus() {
	fmt.Println("\n--- Server Status ---")
	prettyJSON(getJSON("/status"))
	fmt.Println()
}

func cmdEnroll(entropyFile string) {
	fmt.Println("\n--- Enroll ---")
	kp := deriveEd25519(entropyFile)
	pubHex := hex.EncodeToString(kp.Public)
	printLabel("pubkey", pubHex[:32]+"...")

	resp := postJSON("/enroll", map[string]string{
		"pubkey_hex": pubHex,
	})
	prettyJSON(resp)
	fmt.Println()
}

func cmdChallenge(entropyFile string) {
	fmt.Println("\n--- Challenge/Verify ---")
	kp := deriveEd25519(entropyFile)
	pubHex := hex.EncodeToString(kp.Public)
	printLabel("pubkey", pubHex[:32]+"...")

	// Step 1: get challenge from server.
	challResp := postJSON("/challenge", map[string]string{})
	challengeHex, _ := challResp["challenge_hex"].(string)
	printLabel("challenge", challengeHex[:32]+"...")

	// Step 2: sign the challenge locally.
	challenge := must(hex.DecodeString(challengeHex))
	sig := must(cryptolib.Ed25519Sign(challenge, kp.Secret))
	sigHex := hex.EncodeToString(sig)
	printLabel("signature", sigHex[:32]+"...")

	// Step 3: verify with the server.
	verifyResp := postJSON("/verify", map[string]string{
		"challenge_hex": challengeHex,
		"signature_hex": sigHex,
		"pubkey_hex":    pubHex,
	})
	prettyJSON(verifyResp)
	fmt.Println()
}

func cmdEncrypt(message string) map[string]any {
	fmt.Println("\n--- Encrypt ---")
	printLabel("plaintext", message)
	resp := postJSON("/encrypt", map[string]string{
		"plaintext": message,
	})
	if ct, ok := resp["ciphertext_hex"].(string); ok && len(ct) > 32 {
		printLabel("ciphertext", ct[:32]+"...")
	}
	if kid, ok := resp["key_id"].(string); ok {
		printLabel("key_id", kid)
	}
	fmt.Println()
	return resp
}

func cmdDecrypt(ciphertextHex, keyID string) {
	fmt.Println("\n--- Decrypt ---")
	printLabel("key_id", keyID)
	if len(ciphertextHex) > 32 {
		printLabel("ciphertext", ciphertextHex[:32]+"...")
	}
	resp := postJSON("/decrypt", map[string]string{
		"ciphertext_hex": ciphertextHex,
		"key_id":         keyID,
	})
	if pt, ok := resp["plaintext"].(string); ok {
		printLabel("plaintext", pt)
	}
	if errMsg, ok := resp["error"].(string); ok {
		printLabel("error", errMsg)
	}
	fmt.Println()
}

func cmdRotate() {
	fmt.Println("\n--- Rotate ---")
	prettyJSON(getJSON("/rotate"))
	fmt.Println()
}

func cmdDemo(entropyFile string) {
	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  LavaRand Client Demo")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("  Your file is your IDENTITY (deterministic Ed25519).")
	fmt.Println("  The server's file is its ENTROPY SOURCE (LavaRand PRNG).")
	fmt.Println("  They are independent — the server never sees your file.")

	// Step 1: Enroll.
	fmt.Println("\n[1/5] Enroll")
	kp := deriveEd25519(entropyFile)
	pubHex := hex.EncodeToString(kp.Public)
	enrollResp := postJSON("/enroll", map[string]string{
		"pubkey_hex": pubHex,
	})
	enrolled, _ := enrollResp["enrolled"].(bool)
	printLabel("pubkey", pubHex[:32]+"...")
	if fp, ok := enrollResp["server_fingerprint"].(string); ok && len(fp) > 32 {
		printLabel("server_fingerprint", fp[:32]+"...")
	}
	printResult("Enrollment", enrolled)

	// Step 2: Challenge/Verify.
	fmt.Println("\n[2/5] Challenge/Verify")
	challResp := postJSON("/challenge", map[string]string{})
	challengeHex, _ := challResp["challenge_hex"].(string)
	printLabel("challenge", challengeHex[:32]+"...")

	challenge := must(hex.DecodeString(challengeHex))
	sig := must(cryptolib.Ed25519Sign(challenge, kp.Secret))
	sigHex := hex.EncodeToString(sig)
	printLabel("signature", sigHex[:32]+"...")

	verifyResp := postJSON("/verify", map[string]string{
		"challenge_hex": challengeHex,
		"signature_hex": sigHex,
		"pubkey_hex":    pubHex,
	})
	verified, _ := verifyResp["verified"].(bool)
	printResult("Signature verification", verified)

	// Step 3: Encrypt.
	testMessage := "Hello from LavaRand client!"
	fmt.Println("\n[3/5] Encrypt")
	printLabel("plaintext", testMessage)
	encResp := postJSON("/encrypt", map[string]string{
		"plaintext": testMessage,
	})
	ciphertextHex, _ := encResp["ciphertext_hex"].(string)
	keyID, _ := encResp["key_id"].(string)
	encOK := ciphertextHex != "" && keyID != ""
	if len(ciphertextHex) > 32 {
		printLabel("ciphertext", ciphertextHex[:32]+"...")
	}
	printLabel("key_id", keyID)
	printResult("Encryption", encOK)

	// Step 4: Decrypt.
	fmt.Println("\n[4/5] Decrypt")
	decResp := postJSON("/decrypt", map[string]string{
		"ciphertext_hex": ciphertextHex,
		"key_id":         keyID,
	})
	plaintext, _ := decResp["plaintext"].(string)
	decOK := plaintext == testMessage
	printLabel("plaintext", plaintext)
	printResult("Decryption roundtrip", decOK)

	// Step 5: Status.
	fmt.Println("\n[5/5] Server Status")
	statusResp := getJSON("/status")
	prettyJSON(statusResp)

	// Summary.
	fmt.Println("\n========================================")
	fmt.Println("  Summary")
	fmt.Println("========================================")
	printResult("Enroll", enrolled)
	printResult("Challenge/Verify", verified)
	printResult("Encrypt", encOK)
	printResult("Decrypt roundtrip", decOK)

	allOK := enrolled && verified && encOK && decOK
	fmt.Println()
	if allOK {
		fmt.Println("  All steps passed.")
	} else {
		fmt.Println("  Some steps failed.")
	}
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: go run ./client/ [--server URL] <command> [args...]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  status                              Show server entropy status")
	fmt.Fprintln(os.Stderr, "  enroll <entropy-file>               Enroll with file-derived Ed25519 pubkey")
	fmt.Fprintln(os.Stderr, "  challenge <entropy-file>            Get challenge, sign with file key, verify")
	fmt.Fprintln(os.Stderr, "  encrypt <message>                   Encrypt a message (server uses LavaRand key)")
	fmt.Fprintln(os.Stderr, "  decrypt <ciphertext_hex> <key_id>   Decrypt with server's ephemeral key")
	fmt.Fprintln(os.Stderr, "  rotate                              Trigger server key rotation")
	fmt.Fprintln(os.Stderr, "  demo <entropy-file>                 Run full demo: enroll -> challenge -> encrypt -> decrypt")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  --server URL    Server URL (default: http://localhost:8443)")
}

func main() {
	// Initialise cryptolib.
	if err := cryptolib.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: cryptolib init: %v\n", err)
		os.Exit(1)
	}

	// Parse --server flag manually to keep positional args clean.
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--server" && i+1 < len(args) {
			serverURL = strings.TrimRight(args[i+1], "/")
			args = append(args[:i], args[i+2:]...)
			break
		}
		if strings.HasPrefix(args[i], "--server=") {
			serverURL = strings.TrimRight(strings.TrimPrefix(args[i], "--server="), "/")
			args = append(args[:i], args[i+1:]...)
			break
		}
	}

	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "status":
		cmdStatus()

	case "enroll":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "error: enroll requires <entropy-file>")
			os.Exit(1)
		}
		cmdEnroll(cmdArgs[0])

	case "challenge":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "error: challenge requires <entropy-file>")
			os.Exit(1)
		}
		cmdChallenge(cmdArgs[0])

	case "encrypt":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "error: encrypt requires <message>")
			os.Exit(1)
		}
		cmdEncrypt(strings.Join(cmdArgs, " "))

	case "decrypt":
		if len(cmdArgs) < 2 {
			fmt.Fprintln(os.Stderr, "error: decrypt requires <ciphertext_hex> <key_id>")
			os.Exit(1)
		}
		cmdDecrypt(cmdArgs[0], cmdArgs[1])

	case "rotate":
		cmdRotate()

	case "demo":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "error: demo requires <entropy-file>")
			os.Exit(1)
		}
		cmdDemo(cmdArgs[0])

	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", cmd)
		usage()
		os.Exit(1)
	}
}
