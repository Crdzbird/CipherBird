// LavaRand HTTP Server — demonstrates real-world LavaRand entropy usage
// with the CryptoLib Go bindings.
//
// Usage:
//
//	go run main.go --entropy-file /path/to/photo.ppm
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Crdzbird/CipherBird/bridge/bindings/go/cryptolib"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Server state
// ═══════════════════════════════════════════════════════════════════════════════

type serverState struct {
	mu                sync.Mutex
	entropyFile       string
	entropy           *cryptolib.Entropy
	enrolledPubkeys   map[string]bool   // hex pubkey -> enrolled
	pendingChallenges map[string][]byte // hex challenge -> raw bytes
	sessionKeys       map[string][]byte // key_id -> symmetric key
	keysGenerated     int
	startTime         time.Time
}

func newServerState(entropyFile string, ent *cryptolib.Entropy) *serverState {
	return &serverState{
		entropyFile:       entropyFile,
		entropy:           ent,
		enrolledPubkeys:   make(map[string]bool),
		pendingChallenges: make(map[string][]byte),
		sessionKeys:       make(map[string][]byte),
		startTime:         time.Now(),
	}
}

// generateUUID returns a hex-encoded 16-byte random ID.
func generateUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// Middleware
// ═══════════════════════════════════════════════════════════════════════════════

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func logRequest(r *http.Request) {
	fmt.Printf("[%s] %s %s\n", time.Now().Format("2006-01-02 15:04:05"), r.Method, r.URL.Path)
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON helpers
// ═══════════════════════════════════════════════════════════════════════════════

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ═══════════════════════════════════════════════════════════════════════════════
// Handlers
// ═══════════════════════════════════════════════════════════════════════════════

// GET /status
func (s *serverState) handleStatus(w http.ResponseWriter, r *http.Request) {
	logRequest(r)
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	s.mu.Lock()
	info := s.entropy.Info()
	keysGen := s.keysGenerated
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"entropy_file":   filepath.Base(s.entropyFile),
		"entropy_bits":   info.EntropyBits,
		"keys_generated": keysGen,
		"uptime_seconds": int(time.Since(s.startTime).Seconds()),
	})
}

// POST /enroll
func (s *serverState) handleEnroll(w http.ResponseWriter, r *http.Request) {
	logRequest(r)
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}

	var req struct {
		PubkeyHex string `json:"pubkey_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.PubkeyHex == "" {
		writeError(w, http.StatusBadRequest, "pubkey_hex required")
		return
	}

	// Derive a deterministic fingerprint from the entropy file.
	detEnt, err := cryptolib.EntropyFromFileDeterministic(s.entropyFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "entropy error: "+err.Error())
		return
	}
	defer detEnt.Close()
	raw, err := detEnt.Raw()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "fingerprint error: "+err.Error())
		return
	}

	// SHA-256 of the raw entropy as a compact fingerprint.
	fingerprint, err := cryptolib.SHA256(raw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash error: "+err.Error())
		return
	}

	s.mu.Lock()
	s.enrolledPubkeys[req.PubkeyHex] = true
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"enrolled":           true,
		"server_fingerprint": hex.EncodeToString(fingerprint),
	})
}

// POST /challenge
func (s *serverState) handleChallenge(w http.ResponseWriter, r *http.Request) {
	logRequest(r)
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}

	challenge, err := cryptolib.RandomBytes(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "random error: "+err.Error())
		return
	}
	challengeHex := hex.EncodeToString(challenge)

	s.mu.Lock()
	s.pendingChallenges[challengeHex] = challenge
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{
		"challenge_hex": challengeHex,
	})
}

// POST /verify
func (s *serverState) handleVerify(w http.ResponseWriter, r *http.Request) {
	logRequest(r)
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}

	var req struct {
		ChallengeHex string `json:"challenge_hex"`
		SignatureHex string `json:"signature_hex"`
		PubkeyHex    string `json:"pubkey_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	s.mu.Lock()
	challenge, exists := s.pendingChallenges[req.ChallengeHex]
	if exists {
		delete(s.pendingChallenges, req.ChallengeHex)
	}
	s.mu.Unlock()

	if !exists {
		writeJSON(w, http.StatusOK, map[string]any{
			"verified": false,
			"message":  "challenge not found or already used",
		})
		return
	}

	sig, err := hex.DecodeString(req.SignatureHex)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"verified": false,
			"message":  "invalid signature hex",
		})
		return
	}
	pubkey, err := hex.DecodeString(req.PubkeyHex)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"verified": false,
			"message":  "invalid pubkey hex",
		})
		return
	}

	ok := cryptolib.Ed25519Verify(challenge, sig, pubkey)
	msg := "signature verified"
	if !ok {
		msg = "signature verification failed"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"verified": ok,
		"message":  msg,
	})
}

// POST /encrypt
func (s *serverState) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	logRequest(r)
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}

	var req struct {
		Plaintext string `json:"plaintext"`
		AAD       string `json:"aad"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Plaintext == "" {
		writeError(w, http.StatusBadRequest, "plaintext required")
		return
	}

	// Fresh LavaRand key for every encryption (the core demo).
	ent, err := cryptolib.EntropyFromFile(s.entropyFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "entropy error: "+err.Error())
		return
	}
	defer ent.Close()

	key, err := ent.SymmetricKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key derivation error: "+err.Error())
		return
	}

	var aad []byte
	if req.AAD != "" {
		aad = []byte(req.AAD)
	}
	ciphertext, err := cryptolib.XChaCha20Encrypt([]byte(req.Plaintext), key, aad)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encrypt error: "+err.Error())
		return
	}

	keyID, err := generateUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "uuid error: "+err.Error())
		return
	}

	s.mu.Lock()
	s.sessionKeys[keyID] = key
	s.keysGenerated++
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{
		"ciphertext_hex": hex.EncodeToString(ciphertext),
		"key_id":         keyID,
	})
}

// POST /decrypt
func (s *serverState) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	logRequest(r)
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}

	var req struct {
		CiphertextHex string `json:"ciphertext_hex"`
		KeyID         string `json:"key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	s.mu.Lock()
	key, exists := s.sessionKeys[req.KeyID]
	if exists {
		delete(s.sessionKeys, req.KeyID) // ephemeral — forward secrecy
	}
	s.mu.Unlock()

	if !exists {
		writeError(w, http.StatusNotFound, "key_id not found or already consumed")
		return
	}

	ciphertext, err := hex.DecodeString(req.CiphertextHex)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ciphertext hex")
		return
	}

	plaintext, err := cryptolib.XChaCha20Decrypt(ciphertext, key, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "decrypt error: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"plaintext": string(plaintext),
	})
}

// GET /rotate
func (s *serverState) handleRotate(w http.ResponseWriter, r *http.Request) {
	logRequest(r)
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}

	s.mu.Lock()
	s.entropy.Refresh()
	keysGen := s.keysGenerated
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"rotated":        true,
		"keys_generated": keysGen,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

func main() {
	entropyFile := flag.String("entropy-file", "", "Path to LavaRand media file (required)")
	flag.Parse()

	if *entropyFile == "" {
		fmt.Fprintln(os.Stderr, "error: --entropy-file is required")
		flag.Usage()
		os.Exit(1)
	}

	// Initialise cryptolib.
	if err := cryptolib.Init(); err != nil {
		log.Fatalf("cryptolib init: %v", err)
	}

	// Harvest initial entropy from the file.
	ent, err := cryptolib.EntropyFromFile(*entropyFile)
	if err != nil {
		log.Fatalf("entropy from file: %v", err)
	}
	info := ent.Info()

	// Startup banner.
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║            CryptoLib LavaRand HTTP Server                   ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Library version : %-40s ║\n", cryptolib.Version())
	fmt.Printf("║  Entropy file    : %-40s ║\n", filepath.Base(*entropyFile))
	fmt.Printf("║  File size       : %-40s ║\n", fmt.Sprintf("%d bytes", info.FileSize))
	fmt.Printf("║  Chunks read     : %-40d ║\n", info.ChunksRead)
	fmt.Printf("║  Entropy bits    : %-40.0f ║\n", info.EntropyBits)
	fmt.Printf("║  Listening on    : %-40s ║\n", "http://localhost:8443")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Endpoints:                                                 ║")
	fmt.Println("║    GET  /status    — server status and entropy info          ║")
	fmt.Println("║    POST /enroll    — enroll a client public key              ║")
	fmt.Println("║    POST /challenge — get a random 32-byte challenge          ║")
	fmt.Println("║    POST /verify    — verify Ed25519 signature on challenge   ║")
	fmt.Println("║    POST /encrypt   — encrypt with fresh LavaRand key         ║")
	fmt.Println("║    POST /decrypt   — decrypt with ephemeral key (one-use)    ║")
	fmt.Println("║    GET  /rotate    — refresh entropy pool                    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	state := newServerState(*entropyFile, ent)

	mux := http.NewServeMux()
	mux.HandleFunc("/status", state.handleStatus)
	mux.HandleFunc("/enroll", state.handleEnroll)
	mux.HandleFunc("/challenge", state.handleChallenge)
	mux.HandleFunc("/verify", state.handleVerify)
	mux.HandleFunc("/encrypt", state.handleEncrypt)
	mux.HandleFunc("/decrypt", state.handleDecrypt)
	mux.HandleFunc("/rotate", state.handleRotate)

	log.Fatal(http.ListenAndServe(":8443", corsMiddleware(mux)))
}
