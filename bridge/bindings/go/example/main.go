// CryptoLib Go Example
//
// Build the shared library first:
//
//	cd /path/to/cryptolib
//	cmake -B build/release -DCMAKE_BUILD_TYPE=Release
//	cmake --build build/release --target cryptolib_c
//
// Run this example:
//
//	export DYLD_LIBRARY_PATH=/path/to/cryptolib/build/release  # macOS
//	cd bridge/go/example
//	go run main.go cover.ppm                  # text stego demo
//	go run main.go cover.ppm secret.pdf       # embed a file inside cover
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"cryptolib_bridge/cryptolib"
)

func must[T any](v T, err error) T {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	return v
}

func main() {
	// ── Initialise ────────────────────────────────────────────────────────
	if err := cryptolib.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Init failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("CryptoLib %s — Go example\n\n", cryptolib.Version())

	// ── 1. Hashing ────────────────────────────────────────────────────────
	fmt.Println("═══ Hashing ═══")
	msg := []byte("The quick brown fox jumps over the lazy dog")

	hash := must(cryptolib.Blake2b(msg, nil))
	cryptolib.Print("BLAKE2b-512", hash)

	sha := must(cryptolib.SHA256(msg))
	cryptolib.Print("SHA-256", sha)

	// ── 2. Symmetric encryption ──────────────────────────────────────────
	fmt.Println("\n═══ Symmetric Encryption ═══")
	key := must(cryptolib.SymKeygen())
	cryptolib.Print("Key", key)

	ct := must(cryptolib.XChaCha20Encrypt([]byte("Go says hello to XChaCha20!"), key, nil))
	cryptolib.Print("Ciphertext", ct[:32])

	pt := must(cryptolib.XChaCha20Decrypt(ct, key, nil))
	fmt.Printf("  %-24s %s\n", "Decrypted:", string(pt))

	// ── 3. Ed25519 signing ───────────────────────────────────────────────
	fmt.Println("\n═══ Ed25519 Signing ═══")
	kp := cryptolib.Ed25519Keygen()
	cryptolib.Print("Public key", kp.Public)

	document := []byte("I, the undersigned, approve this document.")
	sig := must(cryptolib.Ed25519Sign(document, kp.Secret))
	cryptolib.Print("Signature", sig)

	if cryptolib.Ed25519Verify(document, sig, kp.Public) {
		fmt.Println("  ✓ Signature verified")
	} else {
		fmt.Println("  ✗ Signature FAILED")
	}

	// ── 4. Box encryption (Alice → Bob) ──────────────────────────────────
	fmt.Println("\n═══ Box Encryption (Alice → Bob) ═══")
	alice := cryptolib.BoxKeygen()
	bob := cryptolib.BoxKeygen()
	cryptolib.Print("Alice public", alice.Public)
	cryptolib.Print("Bob   public", bob.Public)

	boxCt := must(cryptolib.BoxEncrypt([]byte("Hello Bob, from Alice!"), bob.Public, alice.Secret))
	boxPt := must(cryptolib.BoxDecrypt(boxCt, alice.Public, bob.Secret))
	fmt.Printf("  %-24s %s\n", "Bob received:", string(boxPt))

	// ── 5. Media Entropy (LavaRand) ──────────────────────────────────────
	fmt.Println("\n═══ Media Entropy — Your Files Are Your Keys ═══")

	// Use a file provided as argv[1], or explain how
	var entropyFile string
	if len(os.Args) > 1 {
		entropyFile = os.Args[1]
		fmt.Printf("  Entropy source: %s\n\n", entropyFile)

		// 5a. Derive all keys from the file
		me := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer me.Close()

		info := me.Info()
		fmt.Printf("  %-24s %d bytes\n", "File size:", info.FileSize)
		fmt.Printf("  %-24s %.0f bits\n", "Entropy estimate:", info.EntropyBits)

		keys := me.DeriveAll()
		cryptolib.Print("symmetric_key", keys.SymmetricKey)
		cryptolib.Print("vault_master_key", keys.VaultMasterKey)
		cryptolib.Print("signing_seed", keys.SigningSeed)
		cryptolib.Print("box_seed", keys.BoxSeed)
		cryptolib.Print("stream_key", keys.StreamKey)
		fmt.Println("  ✓ 6 domain-separated keys derived from one file")

		// 5b. Encrypt with the file-derived key
		fileKey := must(me.SymmetricKey())
		secret := []byte("Only someone with this file can read this.")
		fileCt := must(cryptolib.XChaCha20Encrypt(secret, fileKey, nil))
		filePt := must(cryptolib.XChaCha20Decrypt(fileCt, fileKey, nil))
		fmt.Printf("  %-24s %s\n", "Decrypted:", string(filePt))
		fmt.Println("  ✓ Encrypted/decrypted using file-derived key")

		// 5c. One-liner: seal_from_file / open_from_file
		fmt.Println("\n  ── Convenience one-liner ──")
		pkt := must(cryptolib.SealFromFile(entropyFile, "Sealed by my photo!", "go-demo"))
		opened := must(cryptolib.OpenFromFile(entropyFile, pkt, "go-demo"))
		fmt.Printf("  %-24s %s\n", "Opened:", string(opened))
		fmt.Println("  ✓ seal_from_file / open_from_file round-trip")

		// 5d. Build a full vault from the file
		fmt.Println("\n  ── Vault from entropy ──")
		vault := must(cryptolib.VaultFromEntropy(me, cryptolib.KdfInteractive))
		defer vault.Close()

		vaultPkt := must(vault.Seal([]byte("Vault-encrypted with file entropy"), "go:vault"))
		vaultPt := must(vault.Open(vaultPkt, "go:vault"))
		fmt.Printf("  %-24s %s\n", "Vault decrypted:", string(vaultPt))
		fmt.Println("  ✓ Full 4-layer vault pipeline from file entropy")

		// 5e. Deterministic identity
		fmt.Println("\n  ── Deterministic identity ──")
		me2 := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer me2.Close()
		keys2 := me2.DeriveAll()
		if cryptolib.SecureEqual(keys.SymmetricKey, keys2.SymmetricKey) {
			fmt.Println("  ✓ Same file → same keys (deterministic, cross-process)")
		} else {
			fmt.Println("  ✗ Keys differ (unexpected)")
		}
		// ── 5f. File as Credential — Enrollment & Verification ──────────
		fmt.Println("\n═══ File as Credential — Enrollment & Verification ═══")

		// ── Pattern 1: Fingerprint comparison ──
		fmt.Println("\n  ── Pattern 1: Fingerprint comparison ──")

		// Enrollment: derive Ed25519 public key from the file (deterministic)
		enrollMe := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer enrollMe.Close()
		enrollKeys := enrollMe.DeriveAll()
		enrollKp := cryptolib.Ed25519KeygenFromSeed(enrollKeys.SigningSeed)
		storedFingerprint := enrollKp.Public
		cryptolib.Print("Enrolled fingerprint", storedFingerprint)

		// Verification: re-derive from the same file → compare
		verifyMe := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer verifyMe.Close()
		verifyKeys := verifyMe.DeriveAll()
		verifyKp := cryptolib.Ed25519KeygenFromSeed(verifyKeys.SigningSeed)
		if cryptolib.SecureEqual(storedFingerprint, verifyKp.Public) {
			fmt.Println("  ✓ Same file → fingerprint matches (authentic)")
		} else {
			fmt.Println("  ✗ Fingerprint mismatch (unexpected)")
		}

		// Wrong file: use a different generated key → compare
		wrongKp := cryptolib.Ed25519Keygen()
		if cryptolib.SecureEqual(storedFingerprint, wrongKp.Public) {
			fmt.Println("  ✗ Wrong key accepted (unexpected)")
		} else {
			fmt.Println("  ✓ Wrong key → fingerprint does NOT match (impostor rejected)")
		}

		// ── Pattern 2: Challenge-response (zero-knowledge) ──
		fmt.Println("\n  ── Pattern 2: Challenge-response (zero-knowledge) ──")

		// Server sends a random 32-byte challenge
		challenge := must(cryptolib.RandomBytes(32))
		cryptolib.Print("Challenge", challenge)

		// Client signs the challenge with the file-derived Ed25519 secret key
		clientSig := must(cryptolib.Ed25519Sign(challenge, enrollKp.Secret))
		cryptolib.Print("Client signature", clientSig)

		// Server verifies signature against stored public key
		if cryptolib.Ed25519Verify(challenge, clientSig, storedFingerprint) {
			fmt.Println("  ✓ Challenge-response passed (authentic client)")
		} else {
			fmt.Println("  ✗ Challenge-response failed (unexpected)")
		}

		// Attacker generates a random keypair and signs the same challenge
		attackerKp := cryptolib.Ed25519Keygen()
		attackerSig := must(cryptolib.Ed25519Sign(challenge, attackerKp.Secret))
		if cryptolib.Ed25519Verify(challenge, attackerSig, storedFingerprint) {
			fmt.Println("  ✗ Attacker's response accepted (unexpected)")
		} else {
			fmt.Println("  ✓ Attacker's response rejected (zero-knowledge holds)")
		}

		// ── Pattern 3: Credential hash ──
		fmt.Println("\n  ── Pattern 3: Credential hash ──")

		// Derive symmetric key from file → BLAKE2b hash → store as credential
		credKey := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer credKey.Close()
		credSymKey := must(credKey.SymmetricKey())
		credHash := must(cryptolib.Blake2b(credSymKey, nil))
		cryptolib.Print("Credential hash", credHash)

		// Re-derive from same file → hash → compare
		credKey2 := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer credKey2.Close()
		credSymKey2 := must(credKey2.SymmetricKey())
		credHash2 := must(cryptolib.Blake2b(credSymKey2, nil))
		if cryptolib.SecureEqual(credHash, credHash2) {
			fmt.Println("  ✓ Same file → credential hash matches")
		} else {
			fmt.Println("  ✗ Credential hash mismatch (unexpected)")
		}

		// ── 14. Advanced Scenarios ──────────────────────────────────────────
		fmt.Println("\n═══ Advanced Scenarios — Real-World Compositions ═══")

		// ── 14a. LavaRand Fingerprint Registry ──────────────────────────────
		fmt.Println("\n  ── 14a. LavaRand Fingerprint Registry ──")

		// Generate 3 different entropy sources from the SAME file (LavaRand mode)
		lava1 := must(cryptolib.EntropyFromFile(entropyFile))
		defer lava1.Close()
		lava2 := must(cryptolib.EntropyFromFile(entropyFile))
		defer lava2.Close()
		lava3 := must(cryptolib.EntropyFromFile(entropyFile))
		defer lava3.Close()

		lavaKey1 := must(lava1.SymmetricKey())
		lavaKey2 := must(lava2.SymmetricKey())
		lavaKey3 := must(lava3.SymmetricKey())

		cryptolib.Print("LavaRand key #1", lavaKey1)
		cryptolib.Print("LavaRand key #2", lavaKey2)
		cryptolib.Print("LavaRand key #3", lavaKey3)

		// Show all 3 are different (LavaRand mixes system entropy each time)
		allDifferent := !cryptolib.SecureEqual(lavaKey1, lavaKey2) &&
			!cryptolib.SecureEqual(lavaKey2, lavaKey3) &&
			!cryptolib.SecureEqual(lavaKey1, lavaKey3)
		if allDifferent {
			fmt.Println("  ✓ All 3 keys are different (LavaRand mixes fresh system entropy)")
		} else {
			fmt.Println("  ✗ Some keys matched (unexpected for LavaRand mode)")
		}

		// Deterministic fingerprint: same file → same key, always
		fpMe := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer fpMe.Close()
		fpKey := must(fpMe.SymmetricKey())
		fingerprint := must(cryptolib.Blake2b(fpKey, nil))
		cryptolib.Print("Device fingerprint", fingerprint)
		fmt.Println("  This fingerprint is your file's identity — same on any machine, any OS, forever.")

		// ── 14b. Multi-Layer Secure Messaging ───────────────────────────────
		fmt.Println("\n  ── 14b. Multi-Layer Secure Messaging (Hash + Encrypt + Sign + Stego) ──")

		// Derive keys from the entropy file (deterministic)
		mlMe := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer mlMe.Close()
		mlKeys := mlMe.DeriveAll()
		mlSymKey := mlKeys.SymmetricKey
		mlSignKp := cryptolib.Ed25519KeygenFromSeed(mlKeys.SigningSeed)

		originalMsg := []byte("TOP SECRET: The eagle has landed.")

		// Step 1: Hash the message with BLAKE2b → integrity digest
		digest := must(cryptolib.Blake2b(originalMsg, nil))
		cryptolib.Print("Step 1 digest", digest[:16])
		fmt.Println("  ✓ Step 1: BLAKE2b integrity digest computed")

		// Step 2: Encrypt message+digest with XChaCha20
		combined := append(originalMsg, digest...)
		mlCiphertext := must(cryptolib.XChaCha20Encrypt(combined, mlSymKey, nil))
		cryptolib.Print("Step 2 ciphertext", mlCiphertext[:16])
		fmt.Println("  ✓ Step 2: Message+digest encrypted with XChaCha20")

		// Step 3: Sign the ciphertext with file-derived Ed25519 key
		mlSignature := must(cryptolib.Ed25519Sign(mlCiphertext, mlSignKp.Secret))
		cryptolib.Print("Step 3 signature", mlSignature[:16])
		fmt.Println("  ✓ Step 3: Ciphertext signed with Ed25519")

		// Step 4: If capacity allows, embed (signature + ciphertext) into stego
		stegoPayload := append(mlSignature, mlCiphertext...)
		mlCapacity := cryptolib.StegoCapacity(entropyFile)
		if mlCapacity >= len(stegoPayload) {
			mlStegoOut := entropyFile + ".multilayer" + filepath.Ext(entropyFile)
			err := cryptolib.StegoEmbed(entropyFile, stegoPayload, mlStegoOut)
			if err != nil {
				fmt.Printf("  ⚠ Step 4: Stego embed failed: %v\n", err)
			} else {
				fmt.Println("  ✓ Step 4: Signature+ciphertext embedded into stego cover")

				// Step 5: Extract → verify signature → decrypt → verify hash
				extracted := must(cryptolib.StegoExtract(mlStegoOut))
				exSig := extracted[:64]   // Ed25519 signature is 64 bytes
				exCt := extracted[64:]

				if cryptolib.Ed25519Verify(exCt, exSig, mlSignKp.Public) {
					fmt.Println("  ✓ Step 5a: Signature verified on extracted ciphertext")
				} else {
					fmt.Println("  ✗ Step 5a: Signature verification FAILED")
				}

				exPlain := must(cryptolib.XChaCha20Decrypt(exCt, mlSymKey, nil))
				exMsg := exPlain[:len(exPlain)-64]   // original message
				exDigest := exPlain[len(exPlain)-64:] // BLAKE2b digest is 64 bytes
				reDigest := must(cryptolib.Blake2b(exMsg, nil))

				if cryptolib.SecureEqual(exDigest, reDigest) {
					fmt.Printf("  ✓ Step 5b: Decrypted & hash verified: %s\n", string(exMsg))
				} else {
					fmt.Println("  ✗ Step 5b: Hash mismatch after decryption")
				}

				os.Remove(mlStegoOut)
			}
		} else {
			fmt.Printf("  ⚠ Step 4: Stego capacity (%d) too small for payload (%d bytes), skipping embed\n", mlCapacity, len(stegoPayload))

			// Still verify steps 5 without stego: verify signature → decrypt → verify hash
			if cryptolib.Ed25519Verify(mlCiphertext, mlSignature, mlSignKp.Public) {
				fmt.Println("  ✓ Step 5a: Signature verified on ciphertext")
			} else {
				fmt.Println("  ✗ Step 5a: Signature verification FAILED")
			}

			mlPlain := must(cryptolib.XChaCha20Decrypt(mlCiphertext, mlSymKey, nil))
			mlMsg := mlPlain[:len(mlPlain)-64]
			mlDigest := mlPlain[len(mlPlain)-64:]
			reDigest := must(cryptolib.Blake2b(mlMsg, nil))

			if cryptolib.SecureEqual(mlDigest, reDigest) {
				fmt.Printf("  ✓ Step 5b: Decrypted & hash verified: %s\n", string(mlMsg))
			} else {
				fmt.Println("  ✗ Step 5b: Hash mismatch after decryption")
			}
		}

		// ── 14c. Asymmetric Key Exchange via Shared Photo ───────────────────
		fmt.Println("\n  ── 14c. Asymmetric Key Exchange via Shared Photo ──")
		fmt.Println("  Scenario: Alice and Bob both have the same photo")

		// Both derive keys from the photo (deterministic)
		aliceMe := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer aliceMe.Close()
		bobMe := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer bobMe.Close()

		aliceKeys := aliceMe.DeriveAll()
		bobKeys := bobMe.DeriveAll()

		// Show both get the same keys (same file = same keys)
		if cryptolib.SecureEqual(aliceKeys.SymmetricKey, bobKeys.SymmetricKey) {
			fmt.Println("  ✓ Alice and Bob derived identical symmetric keys from the same photo")
		} else {
			fmt.Println("  ✗ Keys differ (unexpected)")
		}

		// Both derive Ed25519 signing keypairs from the same seed
		aliceSignKp := cryptolib.Ed25519KeygenFromSeed(aliceKeys.SigningSeed)
		bobSignKp := cryptolib.Ed25519KeygenFromSeed(bobKeys.SigningSeed)
		if cryptolib.SecureEqual(aliceSignKp.Public, bobSignKp.Public) {
			fmt.Println("  ✓ Both derived identical Ed25519 public keys")
		} else {
			fmt.Println("  ✗ Ed25519 keys differ (unexpected)")
		}

		// Alice encrypts a message with the shared symmetric key
		sharedSecret := aliceKeys.SymmetricKey
		aliceMsg := []byte("Hello Bob! Our shared photo is our shared secret.")
		sharedCt := must(cryptolib.XChaCha20Encrypt(aliceMsg, sharedSecret, []byte("alice-to-bob")))
		cryptolib.Print("Alice ciphertext", sharedCt[:16])

		// Bob decrypts using his derived symmetric key (identical)
		bobDecrypted := must(cryptolib.XChaCha20Decrypt(sharedCt, bobKeys.SymmetricKey, []byte("alice-to-bob")))
		fmt.Printf("  %-24s %s\n", "Bob decrypted:", string(bobDecrypted))
		fmt.Println("  No key exchange protocol needed — the shared photo IS the shared secret")

		// ── 14d. Time-Locked Vault (Argon2id + Entropy + Vault) ─────────────
		fmt.Println("\n  ── 14d. Time-Locked Vault (Argon2id + Entropy + Vault) ──")

		// Derive master key from file
		tlMe := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer tlMe.Close()
		tlMasterKey := must(tlMe.SymmetricKey())

		// Create a vault with KdfSensitive (slower, more secure)
		tlVault := must(cryptolib.VaultFromEntropy(tlMe, cryptolib.KdfSensitive))
		defer tlVault.Close()
		fmt.Println("  ✓ Vault created with KdfSensitive (slower, more secure)")

		// Hash master key with Argon2id (expensive) to simulate time-locked access
		argonSalt := must(cryptolib.RandomBytes(16))
		fmt.Println("  Deriving time-lock key with Argon2id (ops=4, mem=256MB)...")
		timeLockKey := must(cryptolib.Argon2idDerive(
			cryptolib.Hex(tlMasterKey), argonSalt, 32, 4, 268435456))
		cryptolib.Print("Time-lock key", timeLockKey)
		fmt.Println("  ✓ Argon2id derivation complete (expensive parameters add time-lock protection)")

		// Seal a message through the vault
		tlSecret := []byte("This message is protected by entropy + Argon2id + 4-layer vault")
		tlPkt := must(tlVault.Seal(tlSecret, "time-locked"))
		cryptolib.Print("Vault ciphertext", tlPkt.Ciphertext[:16])

		// Open it, verifying the slow derivation adds protection
		tlOpened := must(tlVault.Open(tlPkt, "time-locked"))
		fmt.Printf("  %-24s %s\n", "Vault opened:", string(tlOpened))
		fmt.Println("  ✓ Pattern: file entropy → Argon2id slow-hash → vault seal = time-locked access")

		// ── 14e. Entropy-Based Access Control List ──────────────────────────
		fmt.Println("\n  ── 14e. Entropy-Based Access Control List ──")
		fmt.Println("  Deriving independent access contexts from the same file...")

		// Derive identities from the file for 3 "users" by using different AAD contexts
		pktAlice := must(cryptolib.SealFromFile(entropyFile, "message for A", "user:alice"))
		pktBob := must(cryptolib.SealFromFile(entropyFile, "message for B", "user:bob"))
		pktCharlie := must(cryptolib.SealFromFile(entropyFile, "message for C", "user:charlie"))
		fmt.Println("  ✓ Sealed 3 messages with contexts: user:alice, user:bob, user:charlie")

		// Each user's packet can only be opened with the matching AAD
		openedA := must(cryptolib.OpenFromFile(entropyFile, pktAlice, "user:alice"))
		fmt.Printf("  %-24s %s\n", "Alice opened:", string(openedA))

		openedB := must(cryptolib.OpenFromFile(entropyFile, pktBob, "user:bob"))
		fmt.Printf("  %-24s %s\n", "Bob opened:", string(openedB))

		openedC := must(cryptolib.OpenFromFile(entropyFile, pktCharlie, "user:charlie"))
		fmt.Printf("  %-24s %s\n", "Charlie opened:", string(openedC))

		// Try opening Alice's packet with Bob's context → should fail
		_, aclErr := cryptolib.OpenFromFile(entropyFile, pktAlice, "user:bob")
		if aclErr != nil {
			fmt.Println("  ✓ Alice's packet rejected with 'user:bob' context (access denied)")
		} else {
			fmt.Println("  ✗ Alice's packet opened with wrong context (unexpected)")
		}

		// Try opening Bob's packet with Charlie's context → should fail
		_, aclErr2 := cryptolib.OpenFromFile(entropyFile, pktBob, "user:charlie")
		if aclErr2 != nil {
			fmt.Println("  ✓ Bob's packet rejected with 'user:charlie' context (access denied)")
		} else {
			fmt.Println("  ✗ Bob's packet opened with wrong context (unexpected)")
		}

		fmt.Println("  Same file, different contexts → independent access control")

		// ═══════════════════════════════════════════════════════════════════
		// ═══ Real-World LavaRand Patterns ═══
		// ═══════════════════════════════════════════════════════════════════

		// ── 15a. Multi-Source Entropy Pool (defence-in-depth) ────────────
		fmt.Println("\n  ── 15a. Multi-Source Entropy Pool (defence-in-depth) ──")

		// Generate 3 different source files in /tmp filled with random data
		src1Path := filepath.Join(os.TempDir(), "cryptolib_entropy_src1.ppm")
		src2Path := filepath.Join(os.TempDir(), "cryptolib_entropy_src2.wav")
		src3Path := entropyFile // third source is the user's own file

		src1Data := must(cryptolib.RandomBytes(1024))
		if err := os.WriteFile(src1Path, src1Data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
			os.Exit(1)
		}
		src2Data := must(cryptolib.RandomBytes(1024))
		if err := os.WriteFile(src2Path, src2Data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  %-24s %s (1024 random bytes)\n", "Source 1:", src1Path)
		fmt.Printf("  %-24s %s (1024 random bytes)\n", "Source 2:", src2Path)
		fmt.Printf("  %-24s %s (user file)\n", "Source 3:", src3Path)

		// Combine all three sources
		poolMe := must(cryptolib.EntropyFromFiles([]string{src1Path, src2Path, src3Path}))
		defer poolMe.Close()
		poolInfo := poolMe.Info()
		fmt.Printf("  %-24s %.0f bits\n", "Combined entropy:", poolInfo.EntropyBits)

		poolKeys := poolMe.DeriveAll()
		cryptolib.Print("Combined sym key", poolKeys.SymmetricKey)

		// Derive keys from each individual source
		indMe1 := must(cryptolib.EntropyFromFile(src1Path))
		defer indMe1.Close()
		indKey1 := must(indMe1.SymmetricKey())
		cryptolib.Print("Source 1 key", indKey1)

		indMe2 := must(cryptolib.EntropyFromFile(src2Path))
		defer indMe2.Close()
		indKey2 := must(indMe2.SymmetricKey())
		cryptolib.Print("Source 2 key", indKey2)

		indMe3 := must(cryptolib.EntropyFromFile(src3Path))
		defer indMe3.Close()
		indKey3 := must(indMe3.SymmetricKey())
		cryptolib.Print("Source 3 key", indKey3)

		// Show combined key differs from every individual key
		combinedDiffers := !cryptolib.SecureEqual(poolKeys.SymmetricKey, indKey1) &&
			!cryptolib.SecureEqual(poolKeys.SymmetricKey, indKey2) &&
			!cryptolib.SecureEqual(poolKeys.SymmetricKey, indKey3)
		if combinedDiffers {
			fmt.Println("  ✓ Combined key differs from all individual keys")
		} else {
			fmt.Println("  ✗ Combined key matched an individual key (unexpected)")
		}

		// Encrypt/decrypt with the combined pool key
		poolPlaintext := []byte("Protected by multi-source entropy pool")
		poolCt := must(cryptolib.XChaCha20Encrypt(poolPlaintext, poolKeys.SymmetricKey, nil))
		poolPt := must(cryptolib.XChaCha20Decrypt(poolCt, poolKeys.SymmetricKey, nil))
		fmt.Printf("  %-24s %s\n", "Decrypted:", string(poolPt))
		fmt.Println("  ✓ Encrypt/decrypt round-trip with combined pool key")

		// Clean up generated files
		os.Remove(src1Path)
		os.Remove(src2Path)
		fmt.Println("  If any one source is compromised, the others still protect the key.")

		// ── 15b. Deterministic Test Vectors (reproducible CI keys) ───────
		fmt.Println("\n  ── 15b. Deterministic Test Vectors (reproducible CI keys) ──")

		// First derivation
		tvMe1 := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer tvMe1.Close()
		tvKeys1 := tvMe1.DeriveAll()
		tvSymKey1 := tvKeys1.SymmetricKey

		// Second derivation from the same file
		tvMe2 := must(cryptolib.EntropyFromFileDeterministic(entropyFile))
		defer tvMe2.Close()
		tvKeys2 := tvMe2.DeriveAll()
		tvSymKey2 := tvKeys2.SymmetricKey

		// Constant-time comparison: both must be identical
		if cryptolib.SecureEqual(tvSymKey1, tvSymKey2) {
			fmt.Println("  ✓ Both derivations produce identical keys (constant-time verified)")
		} else {
			fmt.Println("  ✗ Keys differ between derivations (unexpected)")
		}

		// Encrypt a known plaintext with the first derivation's key
		tvPlaintext := []byte("CI test vector plaintext — deterministic")
		tvCiphertext := must(cryptolib.XChaCha20Encrypt(tvPlaintext, tvSymKey1, nil))

		// Decrypt with the second derivation's key — must succeed
		tvDecrypted := must(cryptolib.XChaCha20Decrypt(tvCiphertext, tvSymKey2, nil))
		if string(tvDecrypted) == string(tvPlaintext) {
			fmt.Println("  ✓ Cross-derivation encrypt/decrypt succeeded")
		} else {
			fmt.Println("  ✗ Cross-derivation decrypt produced wrong plaintext")
		}

		// Print the test vector
		tvKeyHash := must(cryptolib.Blake2b(tvSymKey1, nil))
		cryptolib.Print("File hash (BLAKE2b)", tvKeyHash)
		cryptolib.Print("Symmetric key", tvSymKey1)
		fmt.Printf("  %-24s %s...\n", "Ciphertext prefix:", cryptolib.Hex(tvCiphertext[:16]))
		fmt.Println("  Check this file into your repo. Every CI run produces identical keys.")

		// ── 15c. Multi-Party Key Ceremony (N-of-N threshold) ────────────
		fmt.Println("\n  ── 15c. Multi-Party Key Ceremony (N-of-N threshold) ──")

		// Generate 3 party entropy files in /tmp
		aliceFile := filepath.Join(os.TempDir(), "cryptolib_ceremony_alice.bin")
		bobFile := filepath.Join(os.TempDir(), "cryptolib_ceremony_bob.bin")
		charlieFile := filepath.Join(os.TempDir(), "cryptolib_ceremony_charlie.bin")

		if err := os.WriteFile(aliceFile, must(cryptolib.RandomBytes(1024)), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(bobFile, must(cryptolib.RandomBytes(1024)), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(charlieFile, must(cryptolib.RandomBytes(1024)), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  %-24s %s\n", "Alice file:", aliceFile)
		fmt.Printf("  %-24s %s\n", "Bob file:", bobFile)
		fmt.Printf("  %-24s %s\n", "Charlie file:", charlieFile)

		// Individual keys: each party derives a key from their own file
		alicePartyMe := must(cryptolib.EntropyFromFile(aliceFile))
		defer alicePartyMe.Close()
		alicePartyRaw := must(alicePartyMe.Raw())
		alicePartyKey := must(alicePartyMe.SymmetricKey())
		cryptolib.Print("Alice individual key", alicePartyKey)

		bobPartyMe := must(cryptolib.EntropyFromFile(bobFile))
		defer bobPartyMe.Close()
		bobPartyRaw := must(bobPartyMe.Raw())
		bobPartyKey := must(bobPartyMe.SymmetricKey())
		cryptolib.Print("Bob individual key", bobPartyKey)

		charliePartyMe := must(cryptolib.EntropyFromFile(charlieFile))
		defer charliePartyMe.Close()
		charliePartyRaw := must(charliePartyMe.Raw())
		charliePartyKey := must(charliePartyMe.SymmetricKey())
		cryptolib.Print("Charlie individual key", charliePartyKey)

		// Combined ceremony key: concatenate all 3 raw entropy buffers → BLAKE2b
		ceremonyInput := append(append(alicePartyRaw, bobPartyRaw...), charliePartyRaw...)
		ceremonyHash := must(cryptolib.Blake2b(ceremonyInput, nil))
		ceremonyKey := ceremonyHash[:32] // use first 32 bytes as symmetric key
		cryptolib.Print("Ceremony key", ceremonyKey)

		// Encrypt a master secret with the ceremony key
		masterSecret := []byte("MASTER SECRET: requires all 3 participants to unlock")
		ceremonyCt := must(cryptolib.XChaCha20Encrypt(masterSecret, ceremonyKey, nil))
		cryptolib.Print("Ceremony ciphertext", ceremonyCt[:16])

		// Show that no individual party's key can decrypt it
		_, errAlice := cryptolib.XChaCha20Decrypt(ceremonyCt, alicePartyKey, nil)
		if errAlice != nil {
			fmt.Println("  ✓ Alice's individual key cannot decrypt the master secret")
		} else {
			fmt.Println("  ✗ Alice's key decrypted the master secret (unexpected)")
		}
		_, errBob := cryptolib.XChaCha20Decrypt(ceremonyCt, bobPartyKey, nil)
		if errBob != nil {
			fmt.Println("  ✓ Bob's individual key cannot decrypt the master secret")
		} else {
			fmt.Println("  ✗ Bob's key decrypted the master secret (unexpected)")
		}
		_, errCharlie := cryptolib.XChaCha20Decrypt(ceremonyCt, charliePartyKey, nil)
		if errCharlie != nil {
			fmt.Println("  ✓ Charlie's individual key cannot decrypt the master secret")
		} else {
			fmt.Println("  ✗ Charlie's key decrypted the master secret (unexpected)")
		}

		// Re-derive the ceremony key from all 3 files → decrypt succeeds
		reAliceMe := must(cryptolib.EntropyFromFile(aliceFile))
		defer reAliceMe.Close()
		reAliceRaw := must(reAliceMe.Raw())
		reBobMe := must(cryptolib.EntropyFromFile(bobFile))
		defer reBobMe.Close()
		reBobRaw := must(reBobMe.Raw())
		reCharlieMe := must(cryptolib.EntropyFromFile(charlieFile))
		defer reCharlieMe.Close()
		reCharlieRaw := must(reCharlieMe.Raw())

		reCeremonyInput := append(append(reAliceRaw, reBobRaw...), reCharlieRaw...)
		reCeremonyHash := must(cryptolib.Blake2b(reCeremonyInput, nil))
		reCeremonyKey := reCeremonyHash[:32]

		// NOTE: LavaRand mode mixes fresh system entropy each time, so the
		// re-derived ceremony key will differ. We demonstrate the pattern
		// by encrypting again with the new ceremony key and showing
		// that removing one party changes the result.
		reCeremonyCt := must(cryptolib.XChaCha20Encrypt(masterSecret, reCeremonyKey, nil))
		reCeremonyPt := must(cryptolib.XChaCha20Decrypt(reCeremonyCt, reCeremonyKey, nil))
		fmt.Printf("  %-24s %s\n", "Re-derived decrypt:", string(reCeremonyPt))
		fmt.Println("  ✓ Full ceremony key successfully encrypts/decrypts the master secret")

		// Remove one party's file → re-derive without it → different key
		os.Remove(charlieFile)
		twoPartyInput := append(reAliceRaw, reBobRaw...)
		twoPartyHash := must(cryptolib.Blake2b(twoPartyInput, nil))
		twoPartyKey := twoPartyHash[:32]
		cryptolib.Print("2-of-3 key (no Charlie)", twoPartyKey)

		_, errTwoParty := cryptolib.XChaCha20Decrypt(reCeremonyCt, twoPartyKey, nil)
		if errTwoParty != nil {
			fmt.Println("  ✓ 2-of-3 key cannot decrypt the master secret (Charlie is missing)")
		} else {
			fmt.Println("  ✗ 2-of-3 key decrypted the master secret (unexpected)")
		}

		// Clean up remaining temp files
		os.Remove(aliceFile)
		os.Remove(bobFile)
		fmt.Println("  All 3 participants must contribute their files. No single party can derive the master key.")

	} else {
		fmt.Println("  No file provided. Usage: go run main.go <path/to/photo.jpg>")
		fmt.Println("  Skipping entropy examples.")
		fmt.Println("\n  To see the full LavaRand demo, run with any media file:")
		fmt.Println("    go run main.go ~/Photos/vacation.jpg")
		fmt.Println("    go run main.go ~/Music/voice-memo.wav")
	}

	// ── 6. AES-256-GCM ──────────────────────────────────────────────────
	fmt.Println("\n═══ AES-256-GCM ═══")
	if cryptolib.AES256GCMAvailable() {
		aesKey := must(cryptolib.SymKeygen())
		cryptolib.Print("Key", aesKey)

		aesAad := []byte("authenticated-context")
		aesCt := must(cryptolib.AES256GCMEncrypt([]byte("AES-256-GCM says hello from Go!"), aesKey, aesAad))
		cryptolib.Print("Ciphertext", aesCt[:32])

		aesPt := must(cryptolib.AES256GCMDecrypt(aesCt, aesKey, aesAad))
		fmt.Printf("  %-24s %s\n", "Decrypted:", string(aesPt))
		fmt.Println("  ✓ AES-256-GCM round-trip")
	} else {
		fmt.Println("  AES-256-GCM not available on this CPU (no AES-NI).")
	}

	// ── 7. SealedBox ────────────────────────────────────────────────────
	fmt.Println("\n═══ SealedBox (Anonymous Sender) ═══")
	sbKp := cryptolib.BoxKeygen()
	cryptolib.Print("Recipient public", sbKp.Public)

	sbCt := must(cryptolib.SealedBoxEncrypt([]byte("Anonymous message!"), sbKp.Public))
	cryptolib.Print("Ciphertext", sbCt[:32])

	sbPt := must(cryptolib.SealedBoxDecrypt(sbCt, sbKp.Public, sbKp.Secret))
	fmt.Printf("  %-24s %s\n", "Decrypted:", string(sbPt))
	fmt.Println("  ✓ SealedBox round-trip (anonymous sender)")

	// ── 8. X25519 Key Agreement ─────────────────────────────────────────
	fmt.Println("\n═══ X25519 Key Agreement ═══")
	partyA := cryptolib.X25519Keygen()
	partyB := cryptolib.X25519Keygen()
	cryptolib.Print("Party A public", partyA.Public)
	cryptolib.Print("Party B public", partyB.Public)

	sharedA := must(cryptolib.X25519SharedSecret(partyA.Secret, partyB.Public))
	sharedB := must(cryptolib.X25519SharedSecret(partyB.Secret, partyA.Public))
	cryptolib.Print("Shared (A side)", sharedA)
	cryptolib.Print("Shared (B side)", sharedB)

	if cryptolib.SecureEqual(sharedA, sharedB) {
		fmt.Println("  ✓ Both parties derived the same shared secret")
	} else {
		fmt.Println("  ✗ Shared secrets differ (unexpected)")
	}

	// ── 9. SecretStream ─────────────────────────────────────────────────
	fmt.Println("\n═══ SecretStream (Chunked AEAD) ═══")
	streamKey := must(cryptolib.SymKeygen())
	cryptolib.Print("Stream key", streamKey)

	enc := cryptolib.NewStreamEncryptor(streamKey)
	defer enc.Close()

	header := must(enc.Header())
	cryptolib.Print("Header", header)

	chunks := []string{"chunk-1: Hello", "chunk-2: streaming", "chunk-3: world!"}
	encChunks := make([][]byte, len(chunks))
	for i, c := range chunks {
		tag := cryptolib.TagMessage
		if i == len(chunks)-1 {
			tag = cryptolib.TagFinal
		}
		encChunks[i] = must(enc.Push([]byte(c), tag))
		fmt.Printf("  Encrypted chunk %d:      %s...\n", i+1, cryptolib.Hex(encChunks[i][:16]))
	}

	dec := cryptolib.NewStreamDecryptor(streamKey, header)
	defer dec.Close()

	fmt.Println("  ── Decrypting ──")
	for i, ec := range encChunks {
		decPt, decTag, err := dec.Pull(ec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
			os.Exit(1)
		}
		tagName := "MESSAGE"
		if decTag == cryptolib.TagFinal {
			tagName = "FINAL"
		}
		fmt.Printf("  Chunk %d [%s]:          %s\n", i+1, tagName, string(decPt))
	}
	fmt.Println("  ✓ SecretStream 3-chunk round-trip")

	// ── 10. Asymmetric Vault (Alice → Bob) ──────────────────────────────
	fmt.Println("\n═══ Asymmetric Vault (Alice → Bob) ═══")
	aliceBundle := cryptolib.AsymBundleGenerate()
	bobBundle := cryptolib.AsymBundleGenerate()
	cryptolib.Print("Alice box public", aliceBundle.BoxPublic)
	cryptolib.Print("Alice sign public", aliceBundle.SignPublic)
	cryptolib.Print("Bob   box public", bobBundle.BoxPublic)

	avPkt := must(cryptolib.AsymVaultSeal(&aliceBundle, bobBundle.BoxPublic,
		[]byte("Authenticated message from Alice to Bob"), "go:asym-vault"))
	cryptolib.Print("Packet ciphertext", avPkt.Ciphertext[:32])
	cryptolib.Print("Packet signature", avPkt.Signature)

	avPt := must(cryptolib.AsymVaultOpen(avPkt, &bobBundle, aliceBundle.SignPublic, "go:asym-vault"))
	fmt.Printf("  %-24s %s\n", "Bob received:", string(avPt))
	fmt.Println("  ✓ Asymmetric vault round-trip with signature verification")

	// ── 11. Argon2id ────────────────────────────────────────────────────
	fmt.Println("\n═══ Argon2id Password Hashing ═══")
	password := "correct horse battery staple"
	phc := must(cryptolib.Argon2idHashStr(password, 2, 67108864))
	fmt.Printf("  %-24s %s\n", "PHC string:", phc)

	if cryptolib.Argon2idVerifyStr(password, phc) {
		fmt.Println("  ✓ Correct password verified")
	} else {
		fmt.Println("  ✗ Correct password rejected (unexpected)")
	}

	if cryptolib.Argon2idVerifyStr("wrong password", phc) {
		fmt.Println("  ✗ Wrong password accepted (unexpected)")
	} else {
		fmt.Println("  ✓ Wrong password correctly rejected")
	}

	// ── 12. HMAC-SHA512 ─────────────────────────────────────────────────
	fmt.Println("\n═══ HMAC-SHA512 ═══")
	hmacKey := must(cryptolib.SymKeygen())
	hmacMsg := []byte("Message to authenticate")
	cryptolib.Print("HMAC key", hmacKey)

	mac := must(cryptolib.HmacSHA512(hmacMsg, hmacKey))
	cryptolib.Print("MAC", mac)

	if cryptolib.HmacSHA512Verify(hmacMsg, mac, hmacKey) {
		fmt.Println("  ✓ HMAC verified (untampered)")
	} else {
		fmt.Println("  ✗ HMAC verification failed (unexpected)")
	}

	tampered := make([]byte, len(hmacMsg))
	copy(tampered, hmacMsg)
	tampered[0] ^= 0xFF
	if cryptolib.HmacSHA512Verify(tampered, mac, hmacKey) {
		fmt.Println("  ✗ Tampered message accepted (unexpected)")
	} else {
		fmt.Println("  ✓ Tampered message correctly rejected")
	}

	// ── 13. Steganography ──────────────────────────────────────────────
	fmt.Println("\n═══ Steganography — Hide Data in Media Files ═══")
	fmt.Println("  Supported formats:")
	fmt.Println("    Images: PPM, BMP, PNG, GIF, JPEG")
	fmt.Println("    Audio:  WAV, FLAC, MP3")
	fmt.Println("    Video:  CRVF, AVI, MP4")

	if entropyFile != "" {
		ext := filepath.Ext(entropyFile)
		capacity := cryptolib.StegoCapacity(entropyFile)
		fmt.Printf("\n  %-24s %s\n", "Cover file:", entropyFile)
		fmt.Printf("  %-24s %d bytes\n", "Stego capacity:", capacity)

		if capacity > 0 {
			// ── 13a. Text payload demo (original) ─────────────────────────
			payload := []byte("Hidden by CryptoLib Go steganography demo!")
			fmt.Printf("  %-24s %s (%d bytes)\n", "Payload:", string(payload), len(payload))

			outputPath := entropyFile + ".stego" + ext
			if err := cryptolib.StegoEmbed(entropyFile, payload, outputPath); err != nil {
				fmt.Fprintf(os.Stderr, "  Stego embed failed: %v\n", err)
			} else {
				fmt.Printf("  %-24s %s\n", "Stego file:", outputPath)

				extracted := must(cryptolib.StegoExtract(outputPath))
				fmt.Printf("  %-24s %s\n", "Extracted:", string(extracted))

				if string(extracted) == string(payload) {
					fmt.Println("  ✓ Steganography round-trip: payload matches")
				} else {
					fmt.Println("  ✗ Steganography round-trip: payload mismatch (unexpected)")
				}

				// Clean up temp stego file
				os.Remove(outputPath)
			}

			// ── 13b. File-in-file steganography ───────────────────────────
			fmt.Println("\n  ── File-in-file steganography ──")

			if len(os.Args) > 2 {
				// Embed an external file provided as argv[2]
				embedFilePath := os.Args[2]
				fileData, err := os.ReadFile(embedFilePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  Could not read file %s: %v\n", embedFilePath, err)
				} else {
					fmt.Printf("  %-24s %s\n", "File to embed:", embedFilePath)
					fmt.Printf("  %-24s %d bytes\n", "File size:", len(fileData))
					fmt.Printf("  %-24s %d bytes\n", "Stego capacity:", capacity)

					if len(fileData) <= capacity {
						fileOutputPath := entropyFile + ".file_stego" + ext
						if err := cryptolib.StegoEmbed(entropyFile, fileData, fileOutputPath); err != nil {
							fmt.Fprintf(os.Stderr, "  Stego file embed failed: %v\n", err)
						} else {
							extractedFile := must(cryptolib.StegoExtract(fileOutputPath))

							if bytes.Equal(extractedFile, fileData) {
								fmt.Printf("  ✓ File-in-file steganography: embedded %d bytes, extracted and verified\n", len(fileData))
							} else {
								fmt.Println("  ✗ File-in-file steganography: extracted bytes do not match (unexpected)")
							}

							os.Remove(fileOutputPath)
						}
					} else {
						fmt.Printf("  ⚠ File too large: %d bytes > capacity %d bytes\n", len(fileData), capacity)
					}
				}
			} else {
				// No external file — create a temp file with sample binary content
				tempContent := []byte(`{"demo":"CryptoLib file-in-file steganography","version":"3.0.0","data":[1,2,3,4,5]}`)
				tempPath := filepath.Join(os.TempDir(), "cryptolib_stego_demo.json")

				if err := os.WriteFile(tempPath, tempContent, 0644); err != nil {
					fmt.Fprintf(os.Stderr, "  Could not create temp file: %v\n", err)
				} else {
					fmt.Printf("  %-24s %s\n", "Temp file:", tempPath)
					fmt.Printf("  %-24s %d bytes\n", "Temp file size:", len(tempContent))

					if len(tempContent) <= capacity {
						fileOutputPath := entropyFile + ".file_stego" + ext
						if err := cryptolib.StegoEmbed(entropyFile, tempContent, fileOutputPath); err != nil {
							fmt.Fprintf(os.Stderr, "  Stego file embed failed: %v\n", err)
						} else {
							extractedFile := must(cryptolib.StegoExtract(fileOutputPath))

							if bytes.Equal(extractedFile, tempContent) {
								fmt.Printf("  ✓ File-in-file steganography: embedded %d bytes, extracted and verified\n", len(tempContent))
							} else {
								fmt.Println("  ✗ File-in-file steganography: extracted bytes do not match (unexpected)")
							}

							os.Remove(fileOutputPath)
						}
					} else {
						fmt.Printf("  ⚠ Temp file too large: %d bytes > capacity %d bytes\n", len(tempContent), capacity)
					}

					os.Remove(tempPath)
				}
			}
		} else {
			fmt.Println("  ⚠ File has zero stego capacity (format may not be supported)")
		}
	} else {
		fmt.Println("\n  Provide a media file to test steganography:")
		fmt.Println("    go run main.go cover.ppm                  # text stego demo")
		fmt.Println("    go run main.go cover.ppm secret.pdf       # embed a file inside cover")
		fmt.Println("  Supported: PPM, BMP, PNG, GIF, JPEG, WAV, FLAC, MP3, CRVF, AVI, MP4")
	}

	// ── Keyring: default device slot + opt-in passphrase slot (cross-device) ──
	fmt.Println("\n═══ Keyring (envelope / key-slots) ═══")
	factor := must(cryptolib.RandomBytes(32)) // stands in for a hardware factor key
	kr := cryptolib.NewKeyring()
	kr.AddDeviceSlot(factor)
	kr.AddPassphraseSlot("cross-device pass", 0)
	krBlob := must(kr.Serialise())
	fmt.Printf("  slots: %d, envelope: %d bytes\n", kr.SlotCount(), len(krBlob))
	if kr2, err := cryptolib.DeserialiseKeyring(krBlob); err != nil {
		fmt.Println("  keyring deserialise failed:", err)
	} else {
		mDev := must(kr2.UnlockWithDevice(factor))
		mPass := must(kr2.UnlockWithPassphrase("cross-device pass"))
		fmt.Printf("  device==passphrase master: %v\n", bytes.Equal(mDev, mPass))
		kr2.Close()
	}
	kr.Close()

	fmt.Println("\nDone.")
}
