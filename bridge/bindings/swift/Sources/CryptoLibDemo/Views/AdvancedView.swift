import SwiftUI

@Observable
final class AdvancedViewModel {
    var selectedFilePath: String?
    var errorMessage: String?

    // MARK: - Section 1: LavaRand Fingerprint
    var fingerprint: Data?
    var verifyResult: String?
    var verifyIsMatch: Bool?

    // MARK: - Section 2: Multi-Layer Secure Message
    var messageInput = "The quick brown fox jumps over the lazy dog"
    var integrityHash: Data?
    var ciphertext: Data?
    var signature: Data?
    var signingPublicKey: Data?
    var encryptionKey: Data?
    var signingSecretKey: Data?
    var recoveredPlaintext: String?
    var multiLayerError: String?

    // MARK: - Section 3: Shared Photo Key Exchange
    var alicePublicKey: Data?
    var bobPublicKey: Data?
    var keysMatch: Bool?
    var boxCiphertext: Data?
    var boxDecryptedMessage: String?
    var keyExchangeError: String?

    // MARK: - Section 4: Context-Based Access Control
    var aliceMessage = "Top secret for Alice"
    var bobMessage = "Confidential for Bob"
    var charlieMessage = "Eyes only for Charlie"
    var sealedAlice: PacketResult?
    var sealedBob: PacketResult?
    var sealedCharlie: PacketResult?
    var openResults: [String] = []
    var crossAttackResults: [String] = []

    // MARK: - Section 5: Multi-Source Entropy Pool
    var source2Path: String?
    var source3Path: String?
    var entropyKey1: Data?
    var entropyKey2: Data?
    var entropyKey3: Data?
    var combinedEntropyKey: Data?
    var entropyPoolCiphertext: Data?
    var entropyPoolDecrypted: String?
    var entropyPoolVerification: String?
    var entropyPoolError: String?

    // MARK: - Section 6: Deterministic Test Vectors
    var testVectorFingerprint: Data?
    var testVectorKey: Data?
    var testVectorCiphertextPrefix: String?
    var testVectorKeysMatch: Bool?
    var testVectorDecrypted: String?
    var testVectorError: String?

    // MARK: - Section 7: Multi-Party Key Ceremony
    var aliceCeremonyPath: String?
    var bobCeremonyPath: String?
    var charlieCeremonyPath: String?
    var ceremonyAliceKey: Data?
    var ceremonyBobKey: Data?
    var ceremonyCharlieKey: Data?
    var ceremonyCombinedKey: Data?
    var ceremonyMasterCiphertext: Data?
    var ceremonyIndividualResults: [String] = []
    var ceremonyCeremonyDecrypted: String?
    var ceremonyError: String?

    // MARK: - Section 1 Actions

    /// Derive a deterministic symmetric key from the file (same file = same key always).
    /// Uses from_file_deterministic — NOT from_file (LavaRand) which mixes system entropy.
    private func deterministicKey(bridge: CryptoLibBridge, path: String) throws -> Data {
        let handle = try bridge.entropyFromFile(path, deterministic: true)
        let key = try bridge.entropySymmetricKey(handle)
        bridge.entropyFree(handle)
        return key
    }

    func generateFingerprint(bridge: CryptoLibBridge) {
        guard let path = selectedFilePath else {
            errorMessage = "Select a file first"
            return
        }
        errorMessage = nil
        verifyResult = nil
        verifyIsMatch = nil
        do {
            let key = try deterministicKey(bridge: bridge, path: path)
            let hash = try bridge.blake2b(key)
            fingerprint = hash
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func verifyFingerprint(bridge: CryptoLibBridge) {
        guard let path = selectedFilePath, let stored = fingerprint else {
            errorMessage = "Generate a fingerprint first"
            return
        }
        errorMessage = nil
        do {
            let key = try deterministicKey(bridge: bridge, path: path)
            let hash = try bridge.blake2b(key)
            let match = bridge.secureEqual(hash, stored)
            verifyIsMatch = match
            verifyResult = match
                ? "Fingerprint MATCHES (constant-time comparison)"
                : "Fingerprint MISMATCH"
        } catch {
            verifyResult = "Verification error: \(error.localizedDescription)"
            verifyIsMatch = false
        }
    }

    // MARK: - Section 2 Actions

    func encryptSignHash(bridge: CryptoLibBridge) {
        guard let path = selectedFilePath else {
            multiLayerError = "Select a file first"
            return
        }
        multiLayerError = nil
        recoveredPlaintext = nil
        do {
            let msgData = Data(messageInput.utf8)

            // Step 1: BLAKE2b hash for integrity
            let hash = try bridge.blake2b(msgData)
            integrityHash = hash

            // Step 2: Derive deterministic symmetric key from file and encrypt
            let key = try deterministicKey(bridge: bridge, path: path)
            encryptionKey = key
            let ct = try bridge.xchacha20Encrypt(msgData, key: key)
            ciphertext = ct

            // Step 3: Derive Ed25519 signing key from file
            let handle = try bridge.entropyFromFile(path, deterministic: true)
            let keys = bridge.entropyDeriveAll(handle)
            bridge.entropyFree(handle)
            let sigKp = bridge.ed25519KeygenFromSeed(keys.signingSeed)
            signingPublicKey = sigKp.publicKey
            signingSecretKey = sigKp.secretKey

            // Step 4: Sign the ciphertext
            let sig = try bridge.ed25519Sign(ct, secretKey: sigKp.secretKey)
            signature = sig
        } catch {
            multiLayerError = error.localizedDescription
        }
    }

    func verifyDecrypt(bridge: CryptoLibBridge) {
        guard let ct = ciphertext,
              let sig = signature,
              let pubKey = signingPublicKey,
              let key = encryptionKey,
              let storedHash = integrityHash else {
            multiLayerError = "Encrypt + Sign first"
            return
        }
        multiLayerError = nil
        do {
            // Step 1: Verify signature on ciphertext
            let sigValid = bridge.ed25519Verify(ct, sig: sig, publicKey: pubKey)
            guard sigValid else {
                multiLayerError = "Signature verification FAILED — ciphertext tampered"
                return
            }

            // Step 2: Decrypt
            let plainData = try bridge.xchacha20Decrypt(ct, key: key)

            // Step 3: Verify integrity hash
            let reHash = try bridge.blake2b(plainData)
            let hashMatch = bridge.secureEqual(reHash, storedHash)
            guard hashMatch else {
                multiLayerError = "Integrity hash MISMATCH — data corrupted"
                return
            }

            recoveredPlaintext = String(data: plainData, encoding: .utf8)
                ?? plainData.hexString
        } catch {
            multiLayerError = error.localizedDescription
        }
    }

    // MARK: - Section 3 Actions

    func simulateKeyExchange(bridge: CryptoLibBridge) {
        guard let path = selectedFilePath else {
            keyExchangeError = "Select a file first"
            return
        }
        keyExchangeError = nil
        boxDecryptedMessage = nil
        do {
            // Alice derives Ed25519 keypair from the file
            let aliceHandle = try bridge.entropyFromFile(path, deterministic: true)
            let aliceKeys = bridge.entropyDeriveAll(aliceHandle)
            bridge.entropyFree(aliceHandle)
            let aliceSignKp = bridge.ed25519KeygenFromSeed(aliceKeys.signingSeed)

            // Bob derives Ed25519 keypair from the SAME file
            let bobHandle = try bridge.entropyFromFile(path, deterministic: true)
            let bobKeys = bridge.entropyDeriveAll(bobHandle)
            bridge.entropyFree(bobHandle)
            let bobSignKp = bridge.ed25519KeygenFromSeed(bobKeys.signingSeed)

            alicePublicKey = aliceSignKp.publicKey
            bobPublicKey = bobSignKp.publicKey
            keysMatch = bridge.secureEqual(aliceSignKp.publicKey, bobSignKp.publicKey)

            // For Box encrypt/decrypt, generate ephemeral keypairs
            let aliceBoxKp = bridge.boxKeygen()
            let bobBoxKp = bridge.boxKeygen()

            let secret = "Hello Bob, this is Alice using our shared photo!"
            let msgData = Data(secret.utf8)

            // Alice encrypts to Bob
            let ct = try bridge.boxEncrypt(msgData, recipientPub: bobBoxKp.publicKey,
                                           senderSec: aliceBoxKp.secretKey)
            boxCiphertext = ct

            // Bob decrypts from Alice
            let pt = try bridge.boxDecrypt(ct, senderPub: aliceBoxKp.publicKey,
                                           recipientSec: bobBoxKp.secretKey)
            boxDecryptedMessage = String(data: pt, encoding: .utf8) ?? pt.hexString
        } catch {
            keyExchangeError = error.localizedDescription
        }
    }

    // MARK: - Section 4 Actions

    func sealAll(bridge: CryptoLibBridge) {
        guard let path = selectedFilePath else {
            errorMessage = "Select a file first"
            return
        }
        errorMessage = nil
        openResults = []
        crossAttackResults = []
        do {
            sealedAlice = try bridge.sealFromFile(path, plaintext: aliceMessage, aad: "alice-context")
            sealedBob = try bridge.sealFromFile(path, plaintext: bobMessage, aad: "bob-context")
            sealedCharlie = try bridge.sealFromFile(path, plaintext: charlieMessage, aad: "charlie-context")
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func openCorrectly(bridge: CryptoLibBridge) {
        guard let path = selectedFilePath,
              let pktA = sealedAlice,
              let pktB = sealedBob,
              let pktC = sealedCharlie else {
            errorMessage = "Seal all messages first"
            return
        }
        openResults = []
        do {
            let a = try bridge.openFromFile(path, packet: pktA, aad: "alice-context")
            openResults.append("Alice: \(String(data: a, encoding: .utf8) ?? "?")")
        } catch {
            openResults.append("Alice: FAILED — \(error.localizedDescription)")
        }
        do {
            let b = try bridge.openFromFile(path, packet: pktB, aad: "bob-context")
            openResults.append("Bob: \(String(data: b, encoding: .utf8) ?? "?")")
        } catch {
            openResults.append("Bob: FAILED — \(error.localizedDescription)")
        }
        do {
            let c = try bridge.openFromFile(path, packet: pktC, aad: "charlie-context")
            openResults.append("Charlie: \(String(data: c, encoding: .utf8) ?? "?")")
        } catch {
            openResults.append("Charlie: FAILED — \(error.localizedDescription)")
        }
    }

    func crossContextAttack(bridge: CryptoLibBridge) {
        guard let path = selectedFilePath,
              let pktA = sealedAlice,
              let pktB = sealedBob else {
            errorMessage = "Seal all messages first"
            return
        }
        crossAttackResults = []

        // Try opening Alice's packet with Bob's AAD
        do {
            let _ = try bridge.openFromFile(path, packet: pktA, aad: "bob-context")
            crossAttackResults.append("Alice with bob-context: UNEXPECTED SUCCESS")
        } catch {
            crossAttackResults.append("Alice with bob-context: REJECTED (expected)")
        }

        // Try opening Bob's packet with Charlie's AAD
        do {
            let _ = try bridge.openFromFile(path, packet: pktB, aad: "charlie-context")
            crossAttackResults.append("Bob with charlie-context: UNEXPECTED SUCCESS")
        } catch {
            crossAttackResults.append("Bob with charlie-context: REJECTED (expected)")
        }

        // Try opening Alice's packet with empty AAD
        do {
            let _ = try bridge.openFromFile(path, packet: pktA, aad: "")
            crossAttackResults.append("Alice with empty AAD: UNEXPECTED SUCCESS")
        } catch {
            crossAttackResults.append("Alice with empty AAD: REJECTED (expected)")
        }
    }

    // MARK: - Section 5 Actions

    func combineEntropySources(bridge: CryptoLibBridge) {
        guard let path1 = selectedFilePath,
              let path2 = source2Path,
              let path3 = source3Path else {
            entropyPoolError = "Select all three source files first"
            return
        }
        entropyPoolError = nil
        entropyPoolDecrypted = nil
        entropyPoolCiphertext = nil
        entropyPoolVerification = nil
        do {
            // Derive individual keys
            let key1 = try bridge.keyFromFile(path1)
            let key2 = try bridge.keyFromFile(path2)
            let key3 = try bridge.keyFromFile(path3)
            entropyKey1 = key1
            entropyKey2 = key2
            entropyKey3 = key3

            // Combine: concatenate all 3 keys then BLAKE2b hash
            var combined = Data()
            combined.append(key1)
            combined.append(key2)
            combined.append(key3)
            let combinedKey = try bridge.blake2b(combined)
            combinedEntropyKey = combinedKey

            // Verify combined differs from all individuals
            let diffFrom1 = !bridge.secureEqual(combinedKey, key1)
            let diffFrom2 = !bridge.secureEqual(combinedKey, key2)
            let diffFrom3 = !bridge.secureEqual(combinedKey, key3)
            if diffFrom1 && diffFrom2 && diffFrom3 {
                entropyPoolVerification = "Combined key differs from all individual keys"
            } else {
                entropyPoolVerification = "WARNING: Combined key matches an individual key"
            }

            // Encrypt with combined key
            let plaintext = Data("Multi-source entropy pool test message".utf8)
            let ct = try bridge.xchacha20Encrypt(plaintext, key: combinedKey)
            entropyPoolCiphertext = ct

            // Decrypt with combined key
            let pt = try bridge.xchacha20Decrypt(ct, key: combinedKey)
            entropyPoolDecrypted = String(data: pt, encoding: .utf8) ?? pt.hexString
        } catch {
            entropyPoolError = error.localizedDescription
        }
    }

    // MARK: - Section 6 Actions

    func generateTestVector(bridge: CryptoLibBridge) {
        guard let path = selectedFilePath else {
            testVectorError = "Select a source file first (uses main file picker)"
            return
        }
        testVectorError = nil
        testVectorDecrypted = nil
        testVectorCiphertextPrefix = nil
        do {
            // Derive key twice (deterministic), verify match
            let key1 = try bridge.keyFromFile(path)
            let key2 = try bridge.keyFromFile(path)
            let keysMatch = bridge.secureEqual(key1, key2)
            testVectorKeysMatch = keysMatch

            testVectorKey = key1

            // Fingerprint = BLAKE2b of key
            let fingerprint = try bridge.blake2b(key1)
            testVectorFingerprint = fingerprint

            // Encrypt known plaintext
            let knownPlaintext = Data("deterministic test vector plaintext".utf8)
            let ct = try bridge.xchacha20Encrypt(knownPlaintext, key: key1)
            let prefixBytes = min(ct.count, 32)
            testVectorCiphertextPrefix = ct.prefix(prefixBytes).hexString

            // Decrypt with second derivation
            let pt = try bridge.xchacha20Decrypt(ct, key: key2)
            testVectorDecrypted = String(data: pt, encoding: .utf8) ?? pt.hexString
        } catch {
            testVectorError = error.localizedDescription
        }
    }

    // MARK: - Section 7 Actions

    func runKeyCeremony(bridge: CryptoLibBridge) {
        guard let aPath = aliceCeremonyPath,
              let bPath = bobCeremonyPath,
              let cPath = charlieCeremonyPath else {
            ceremonyError = "Select files for all three participants"
            return
        }
        ceremonyError = nil
        ceremonyIndividualResults = []
        ceremonyCeremonyDecrypted = nil
        do {
            // Derive individual keys
            let aKey = try bridge.keyFromFile(aPath)
            let bKey = try bridge.keyFromFile(bPath)
            let cKey = try bridge.keyFromFile(cPath)
            ceremonyAliceKey = aKey
            ceremonyBobKey = bKey
            ceremonyCharlieKey = cKey

            // Combine via concatenation + BLAKE2b
            var combined = Data()
            combined.append(aKey)
            combined.append(bKey)
            combined.append(cKey)
            let ceremonyKey = try bridge.blake2b(combined)
            ceremonyCombinedKey = ceremonyKey

            // Encrypt master secret with ceremony key
            let masterSecret = Data("MASTER SECRET: launch codes 1234".utf8)
            let ct = try bridge.xchacha20Encrypt(masterSecret, key: ceremonyKey)
            ceremonyMasterCiphertext = ct
        } catch {
            ceremonyError = error.localizedDescription
        }
    }

    func tryIndividualDecrypt(bridge: CryptoLibBridge) {
        guard let ct = ceremonyMasterCiphertext else {
            ceremonyError = "Run key ceremony first"
            return
        }
        ceremonyIndividualResults = []

        // Try Alice's key alone
        if let aKey = ceremonyAliceKey {
            do {
                let _ = try bridge.xchacha20Decrypt(ct, key: aKey)
                ceremonyIndividualResults.append("Alice alone: UNEXPECTED SUCCESS")
            } catch {
                ceremonyIndividualResults.append("Alice alone: FAILED (expected)")
            }
        }

        // Try Bob's key alone
        if let bKey = ceremonyBobKey {
            do {
                let _ = try bridge.xchacha20Decrypt(ct, key: bKey)
                ceremonyIndividualResults.append("Bob alone: UNEXPECTED SUCCESS")
            } catch {
                ceremonyIndividualResults.append("Bob alone: FAILED (expected)")
            }
        }

        // Try Charlie's key alone
        if let cKey = ceremonyCharlieKey {
            do {
                let _ = try bridge.xchacha20Decrypt(ct, key: cKey)
                ceremonyIndividualResults.append("Charlie alone: UNEXPECTED SUCCESS")
            } catch {
                ceremonyIndividualResults.append("Charlie alone: FAILED (expected)")
            }
        }
    }

    func ceremonyDecrypt(bridge: CryptoLibBridge) {
        guard let ct = ceremonyMasterCiphertext,
              let key = ceremonyCombinedKey else {
            ceremonyError = "Run key ceremony first"
            return
        }
        ceremonyCeremonyDecrypted = nil
        do {
            let pt = try bridge.xchacha20Decrypt(ct, key: key)
            ceremonyCeremonyDecrypted = String(data: pt, encoding: .utf8) ?? pt.hexString
        } catch {
            ceremonyError = "Ceremony decrypt failed: \(error.localizedDescription)"
        }
    }
}

struct AdvancedView: View {
    let bridge: CryptoLibBridge
    @State private var vm = AdvancedViewModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                headerSection
                filePickerSection

                if let error = vm.errorMessage {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundColor(.red)
                }

                DisclosureGroup("LavaRand Fingerprint") {
                    fingerprintSection
                }

                DisclosureGroup("Multi-Layer Secure Message") {
                    multiLayerSection
                }

                DisclosureGroup("Shared Photo Key Exchange") {
                    keyExchangeSection
                }

                DisclosureGroup("Context-Based Access Control") {
                    accessControlSection
                }

                DisclosureGroup("Multi-Source Entropy Pool") {
                    entropyPoolSection
                }

                DisclosureGroup("Deterministic Test Vectors") {
                    testVectorSection
                }

                DisclosureGroup("Multi-Party Key Ceremony") {
                    keyCeremonySection
                }
            }
            .padding()
        }
        .navigationTitle("Advanced")
    }

    // MARK: - Header

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Advanced Composition")
                .font(.title2.bold())
            Text("Real-world scenarios combining hashing, encryption, signing, entropy, and access control from CryptoLib.")
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - File Picker

    private var filePickerSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Source File (used across all sections)")
                .font(.headline)
            FilePickerButton("Choose Media File",
                             allowedTypes: ["png", "jpg", "jpeg", "ppm", "wav", "mp3", "mp4", "crvf"]) { url in
                vm.selectedFilePath = url.path
            }
        }
    }

    // MARK: - Section 1: LavaRand Fingerprint

    private var fingerprintSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Derive a deterministic symmetric key from a file, then BLAKE2b hash it to create a unique fingerprint. Verify re-derives and compares using constant-time secure_equal.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack(spacing: 12) {
                Button {
                    vm.generateFingerprint(bridge: bridge)
                } label: {
                    Label("Generate Fingerprint", systemImage: "touchid")
                }
                .buttonStyle(.borderedProminent)
                .disabled(vm.selectedFilePath == nil)

                Button {
                    vm.verifyFingerprint(bridge: bridge)
                } label: {
                    Label("Verify", systemImage: "checkmark.shield")
                }
                .buttonStyle(.bordered)
                .disabled(vm.fingerprint == nil)
            }

            if let fp = vm.fingerprint {
                HexView(label: "Fingerprint", data: fp)
            }

            if let result = vm.verifyResult, let isMatch = vm.verifyIsMatch {
                Label(result, systemImage: isMatch ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(isMatch ? .green : .red)
                    .font(.body.weight(.semibold))
            }
        }
        .padding(.top, 8)
    }

    // MARK: - Section 2: Multi-Layer Secure Message

    private var multiLayerSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("BLAKE2b hash (integrity) + XChaCha20 encrypt (confidentiality) + Ed25519 sign (authenticity). Verification reverses all steps.")
                .font(.caption)
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 6) {
                Text("Message")
                    .font(.subheadline.weight(.semibold))
                TextEditor(text: $vm.messageInput)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 50, maxHeight: 80)
                    .padding(4)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(.tertiary))
            }

            HStack(spacing: 12) {
                Button {
                    vm.encryptSignHash(bridge: bridge)
                } label: {
                    Label("Encrypt + Sign + Hash", systemImage: "lock.shield")
                }
                .buttonStyle(.borderedProminent)
                .disabled(vm.selectedFilePath == nil)

                Button {
                    vm.verifyDecrypt(bridge: bridge)
                } label: {
                    Label("Verify + Decrypt", systemImage: "lock.open")
                }
                .buttonStyle(.bordered)
                .disabled(vm.ciphertext == nil)
            }

            if let error = vm.multiLayerError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundColor(.red)
            }

            if let hash = vm.integrityHash {
                HexView(label: "Integrity Hash (BLAKE2b)", data: hash)
            }
            if let ct = vm.ciphertext {
                HexStringView(label: "Ciphertext (XChaCha20)", data: ct)
            }
            if let sig = vm.signature {
                HexStringView(label: "Signature (Ed25519)", data: sig)
            }

            if let recovered = vm.recoveredPlaintext {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Recovered Plaintext")
                        .font(.headline)
                    Text(recovered)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.green.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }
        }
        .padding(.top, 8)
    }

    // MARK: - Section 3: Shared Photo Key Exchange

    private var keyExchangeSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Alice and Bob both possess the same photo. Each derives an Ed25519 keypair deterministically — proving shared knowledge. Then Alice Box-encrypts a message to Bob.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Button {
                vm.simulateKeyExchange(bridge: bridge)
            } label: {
                Label("Simulate Alice & Bob", systemImage: "person.2")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vm.selectedFilePath == nil)

            if let error = vm.keyExchangeError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundColor(.red)
            }

            if let aPub = vm.alicePublicKey, let bPub = vm.bobPublicKey {
                GroupBox("Derived Public Keys") {
                    VStack(alignment: .leading, spacing: 8) {
                        HexStringView(label: "Alice Public Key", data: aPub)
                        HexStringView(label: "Bob Public Key", data: bPub)

                        if let match = vm.keysMatch {
                            Label(
                                match ? "Keys MATCH — same file produces identical identity"
                                      : "Keys DO NOT match",
                                systemImage: match ? "checkmark.circle.fill" : "xmark.circle.fill"
                            )
                            .foregroundColor(match ? .green : .red)
                            .font(.body.weight(.semibold))
                        }
                    }
                    .padding(.vertical, 4)
                }
            }

            if let ct = vm.boxCiphertext {
                HexStringView(label: "Box Ciphertext (Alice -> Bob)", data: ct)
            }

            if let msg = vm.boxDecryptedMessage {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Bob Decrypted")
                        .font(.headline)
                    Text(msg)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.green.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }
        }
        .padding(.top, 8)
    }

    // MARK: - Section 4: Context-Based Access Control

    private var accessControlSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Encrypt three messages with the same file-derived key but different AAD (Additional Authenticated Data) contexts. Each message can only be opened with the correct AAD — wrong context fails authentication.")
                .font(.caption)
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 8) {
                TextField("Message for Alice", text: $vm.aliceMessage)
                    .textFieldStyle(.roundedBorder)
                TextField("Message for Bob", text: $vm.bobMessage)
                    .textFieldStyle(.roundedBorder)
                TextField("Message for Charlie", text: $vm.charlieMessage)
                    .textFieldStyle(.roundedBorder)
            }

            HStack(spacing: 12) {
                Button {
                    vm.sealAll(bridge: bridge)
                } label: {
                    Label("Seal All", systemImage: "lock.rectangle.stack")
                }
                .buttonStyle(.borderedProminent)
                .disabled(vm.selectedFilePath == nil)

                Button {
                    vm.openCorrectly(bridge: bridge)
                } label: {
                    Label("Open Correctly", systemImage: "lock.open")
                }
                .buttonStyle(.bordered)
                .disabled(vm.sealedAlice == nil)

                Button {
                    vm.crossContextAttack(bridge: bridge)
                } label: {
                    Label("Cross-Context Attack", systemImage: "xmark.shield")
                }
                .buttonStyle(.bordered)
                .tint(.red)
                .disabled(vm.sealedAlice == nil)
            }

            if let pkt = vm.sealedAlice {
                GroupBox("Sealed Packets") {
                    VStack(spacing: 8) {
                        HexStringView(label: "Alice (alice-context)", data: pkt.ciphertext)
                        if let pktB = vm.sealedBob {
                            HexStringView(label: "Bob (bob-context)", data: pktB.ciphertext)
                        }
                        if let pktC = vm.sealedCharlie {
                            HexStringView(label: "Charlie (charlie-context)", data: pktC.ciphertext)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }

            if !vm.openResults.isEmpty {
                GroupBox("Correct Context Results") {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(vm.openResults, id: \.self) { result in
                            Label(result, systemImage: "checkmark.circle")
                                .foregroundColor(.green)
                                .font(.system(.caption, design: .monospaced))
                        }
                    }
                    .padding(.vertical, 4)
                }
            }

            if !vm.crossAttackResults.isEmpty {
                GroupBox("Cross-Context Attack Results") {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(vm.crossAttackResults, id: \.self) { result in
                            let isRejected = result.contains("REJECTED")
                            Label(result, systemImage: isRejected ? "xmark.shield" : "exclamationmark.triangle")
                                .foregroundColor(isRejected ? .orange : .red)
                                .font(.system(.caption, design: .monospaced))
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .padding(.top, 8)
    }

    // MARK: - Section 5: Multi-Source Entropy Pool

    private var entropyPoolSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Derive keys from three separate files, then combine them via concatenation + BLAKE2b hashing to produce a single robust key. If any source is compromised, the others still protect the key.")
                .font(.caption)
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 6) {
                Text("Source File 1: uses the main file picker above")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)

                FilePickerButton("Source File 2",
                                 allowedTypes: ["png", "jpg", "jpeg", "ppm", "wav", "mp3", "mp4", "crvf"]) { url in
                    vm.source2Path = url.path
                }

                FilePickerButton("Source File 3",
                                 allowedTypes: ["png", "jpg", "jpeg", "ppm", "wav", "mp3", "mp4", "crvf"]) { url in
                    vm.source3Path = url.path
                }
            }

            Button {
                vm.combineEntropySources(bridge: bridge)
            } label: {
                Label("Combine Entropy Sources", systemImage: "arrow.triangle.merge")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vm.selectedFilePath == nil || vm.source2Path == nil || vm.source3Path == nil)

            if let error = vm.entropyPoolError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundColor(.red)
            }

            if let k1 = vm.entropyKey1 {
                HexStringView(label: "Key 1 (Source 1)", data: k1)
            }
            if let k2 = vm.entropyKey2 {
                HexStringView(label: "Key 2 (Source 2)", data: k2)
            }
            if let k3 = vm.entropyKey3 {
                HexStringView(label: "Key 3 (Source 3)", data: k3)
            }
            if let ck = vm.combinedEntropyKey {
                HexView(label: "Combined Key (BLAKE2b)", data: ck)
            }

            if let verification = vm.entropyPoolVerification {
                Label(verification, systemImage: "checkmark.shield")
                    .foregroundColor(.green)
                    .font(.body.weight(.semibold))
            }

            if let ct = vm.entropyPoolCiphertext {
                HexStringView(label: "Ciphertext (Combined Key)", data: ct)
            }

            if let decrypted = vm.entropyPoolDecrypted {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Decrypted with Combined Key")
                        .font(.headline)
                    Text(decrypted)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.green.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }

            Label("If any source is compromised, the others still protect the key.",
                  systemImage: "info.circle")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.top, 8)
    }

    // MARK: - Section 6: Deterministic Test Vectors

    private var testVectorSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Derive the same key twice from the main source file, verify they match via secureEqual, then encrypt a known plaintext and decrypt with the second derivation.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Button {
                vm.generateTestVector(bridge: bridge)
            } label: {
                Label("Generate Test Vector", systemImage: "testtube.2")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vm.selectedFilePath == nil)

            if let error = vm.testVectorError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundColor(.red)
            }

            if let keysMatch = vm.testVectorKeysMatch {
                Label(keysMatch
                      ? "Deterministic keys MATCH (secureEqual)"
                      : "Deterministic keys DO NOT match",
                      systemImage: keysMatch ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(keysMatch ? .green : .red)
                    .font(.body.weight(.semibold))
            }

            if let fp = vm.testVectorFingerprint,
               let key = vm.testVectorKey,
               let ctPrefix = vm.testVectorCiphertextPrefix {
                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Test Vector")
                            .font(.headline)

                        VStack(alignment: .leading, spacing: 4) {
                            Text("File Fingerprint (BLAKE2b of key)")
                                .font(.caption.weight(.semibold))
                            Text(fp.hexString)
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                                .lineLimit(2)
                                .truncationMode(.middle)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Symmetric Key")
                                .font(.caption.weight(.semibold))
                            Text(key.hexString)
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                                .lineLimit(2)
                                .truncationMode(.middle)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Ciphertext Prefix")
                                .font(.caption.weight(.semibold))
                            Text(ctPrefix)
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                                .lineLimit(2)
                                .truncationMode(.middle)
                        }
                    }
                    .padding(4)
                }
                .backgroundStyle(Color.blue.opacity(0.05))
            }

            if let decrypted = vm.testVectorDecrypted {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Decrypted (2nd derivation)")
                        .font(.headline)
                    Text(decrypted)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.green.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }

            Label("Reproducible \u{2014} same file = same vector on any machine",
                  systemImage: "checkmark.seal")
                .foregroundColor(.green)
                .font(.caption.weight(.semibold))
        }
        .padding(.top, 8)
    }

    // MARK: - Section 7: Multi-Party Key Ceremony

    private var keyCeremonySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Three participants each contribute a file. Individual keys are combined via concatenation + BLAKE2b to form a ceremony key. Only the combined key can decrypt the master secret.")
                .font(.caption)
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 6) {
                FilePickerButton("Alice's File",
                                 allowedTypes: ["png", "jpg", "jpeg", "ppm", "wav", "mp3", "mp4", "crvf"]) { url in
                    vm.aliceCeremonyPath = url.path
                }

                FilePickerButton("Bob's File",
                                 allowedTypes: ["png", "jpg", "jpeg", "ppm", "wav", "mp3", "mp4", "crvf"]) { url in
                    vm.bobCeremonyPath = url.path
                }

                FilePickerButton("Charlie's File",
                                 allowedTypes: ["png", "jpg", "jpeg", "ppm", "wav", "mp3", "mp4", "crvf"]) { url in
                    vm.charlieCeremonyPath = url.path
                }
            }

            Button {
                vm.runKeyCeremony(bridge: bridge)
            } label: {
                Label("Run Key Ceremony", systemImage: "person.3")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vm.aliceCeremonyPath == nil || vm.bobCeremonyPath == nil || vm.charlieCeremonyPath == nil)

            if let error = vm.ceremonyError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundColor(.red)
            }

            if let aKey = vm.ceremonyAliceKey {
                HexStringView(label: "Alice's Key", data: aKey)
            }
            if let bKey = vm.ceremonyBobKey {
                HexStringView(label: "Bob's Key", data: bKey)
            }
            if let cKey = vm.ceremonyCharlieKey {
                HexStringView(label: "Charlie's Key", data: cKey)
            }
            if let ck = vm.ceremonyCombinedKey {
                HexView(label: "Ceremony Key (Combined)", data: ck)
            }

            if vm.ceremonyMasterCiphertext != nil {
                HStack(spacing: 12) {
                    Button {
                        vm.tryIndividualDecrypt(bridge: bridge)
                    } label: {
                        Label("Try Individual Decrypt", systemImage: "person.fill.xmark")
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)

                    Button {
                        vm.ceremonyDecrypt(bridge: bridge)
                    } label: {
                        Label("Ceremony Decrypt", systemImage: "person.3.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
                }
            }

            if !vm.ceremonyIndividualResults.isEmpty {
                GroupBox("Individual Decrypt Attempts") {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(vm.ceremonyIndividualResults, id: \.self) { result in
                            let isFailed = result.contains("FAILED")
                            Label(result, systemImage: isFailed ? "xmark.circle" : "exclamationmark.triangle")
                                .foregroundColor(isFailed ? .orange : .red)
                                .font(.system(.caption, design: .monospaced))
                        }
                    }
                    .padding(.vertical, 4)
                }
            }

            if let decrypted = vm.ceremonyCeremonyDecrypted {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Ceremony Decrypted")
                        .font(.headline)
                    Text(decrypted)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.green.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }

            Label("All participants must contribute. No single party can access alone.",
                  systemImage: "lock.shield")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.top, 8)
    }
}
