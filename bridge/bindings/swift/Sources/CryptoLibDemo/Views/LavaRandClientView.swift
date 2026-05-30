import SwiftUI

// MARK: - Codable Request/Response Types

struct StatusResponse: Codable {
    let status: String
    let version: String
    let uptime_seconds: Double
}

struct EnrollRequest: Codable {
    let pubkey_hex: String
}

struct EnrollResponse: Codable {
    let enrolled: Bool
    let server_fingerprint: String
}

struct ChallengeResponse: Codable {
    let challenge_hex: String
}

struct VerifyRequest: Codable {
    let pubkey_hex: String
    let challenge_hex: String
    let signature_hex: String
}

struct VerifyResponse: Codable {
    let verified: Bool
    let message: String
}

struct EncryptRequest: Codable {
    let plaintext: String
    let aad: String
}

struct EncryptResponse: Codable {
    let ciphertext_hex: String
    let key_id: String
}

struct DecryptRequest: Codable {
    let ciphertext_hex: String
    let key_id: String
}

struct DecryptResponse: Codable {
    let plaintext: String
}

struct RotationResponse: Codable {
    let rotated: Bool
    let new_key_id: String
}

// MARK: - ViewModel

@Observable
@MainActor
final class LavaRandClientViewModel {
    // Connection
    var serverURL = "http://localhost:8443"
    var statusInfo: String?
    var isConnected = false

    // Client identity
    var selectedFilePath: String?
    var publicKeyHex: String?

    // Enroll
    var serverFingerprint: String?

    // Challenge-Response
    var challengeResult: String?

    // Encrypt / Decrypt
    var messageInput = "Hello from CryptoLib SwiftUI client!"
    var lastCiphertextHex: String?
    var lastKeyId: String?
    var recoveredPlaintext: String?

    // Key Rotation
    var rotationResult: String?

    // Full Demo
    var demoLog: [String] = []
    var isDemoRunning = false

    // Errors
    var errorMessage: String?

    // MARK: - Derived Ed25519 keypair

    private var secretKeyData: Data?

    func deriveIdentity(bridge: CryptoLibBridge) {
        guard let path = selectedFilePath else {
            errorMessage = "Select an entropy file first"
            return
        }
        errorMessage = nil
        do {
            let handle = try bridge.entropyFromFile(path, deterministic: true)
            let keys = bridge.entropyDeriveAll(handle)
            bridge.entropyFree(handle)
            let kp = bridge.ed25519KeygenFromSeed(keys.signingSeed)
            publicKeyHex = kp.publicKey.hexString
            secretKeyData = kp.secretKey
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - HTTP Helpers

    private func url(_ endpoint: String) -> URL? {
        URL(string: serverURL.trimmingCharacters(in: .init(charactersIn: "/")) + endpoint)
    }

    private func get<T: Decodable>(_ endpoint: String) async throws -> T {
        guard let requestURL = url(endpoint) else {
            throw CryptoLibError.operationFailed("Invalid URL")
        }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "GET"
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? "unknown"
            throw CryptoLibError.operationFailed("HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0): \(body)")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func postEmpty<Res: Decodable>(_ endpoint: String) async throws -> Res {
        guard let requestURL = url(endpoint) else {
            throw CryptoLibError.operationFailed("Invalid URL")
        }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? "unknown"
            throw CryptoLibError.operationFailed("HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0): \(body)")
        }
        return try JSONDecoder().decode(Res.self, from: data)
    }

    private func post<Req: Encodable, Res: Decodable>(_ endpoint: String, body: Req) async throws -> Res {
        guard let requestURL = url(endpoint) else {
            throw CryptoLibError.operationFailed("Invalid URL")
        }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? "unknown"
            throw CryptoLibError.operationFailed("HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0): \(body)")
        }
        return try JSONDecoder().decode(Res.self, from: data)
    }

    // MARK: - Actions

    func checkStatus() async {
        errorMessage = nil
        do {
            let status: StatusResponse = try await get("/status")
            statusInfo = "Status: \(status.status) | Version: \(status.version) | Uptime: \(String(format: "%.1f", status.uptime_seconds))s"
            isConnected = true
        } catch {
            statusInfo = nil
            isConnected = false
            errorMessage = "Connection failed: \(error.localizedDescription)"
        }
    }

    func enroll() async {
        guard let pubHex = publicKeyHex else {
            errorMessage = "Derive identity first"
            return
        }
        errorMessage = nil
        do {
            let resp: EnrollResponse = try await post("/enroll", body: EnrollRequest(pubkey_hex: pubHex))
            serverFingerprint = resp.server_fingerprint
            if !resp.enrolled {
                errorMessage = "Server declined enrollment"
            }
        } catch {
            errorMessage = "Enroll failed: \(error.localizedDescription)"
        }
    }

    func challengeResponse(bridge: CryptoLibBridge) async {
        guard let pubHex = publicKeyHex, let sk = secretKeyData else {
            errorMessage = "Derive identity first"
            return
        }
        errorMessage = nil
        do {
            // Step 1: Get challenge
            let challenge: ChallengeResponse = try await get("/challenge?pubkey_hex=\(pubHex)")

            // Step 2: Sign the challenge
            let challengeData = Data(hexString: challenge.challenge_hex)
            let signature = try bridge.ed25519Sign(challengeData, secretKey: sk)

            // Step 3: Verify
            let verifyReq = VerifyRequest(
                pubkey_hex: pubHex,
                challenge_hex: challenge.challenge_hex,
                signature_hex: signature.hexString
            )
            let verifyResp: VerifyResponse = try await post("/verify", body: verifyReq)
            challengeResult = verifyResp.verified
                ? "Verified: \(verifyResp.message)"
                : "Verification failed: \(verifyResp.message)"
        } catch {
            errorMessage = "Challenge-Response failed: \(error.localizedDescription)"
        }
    }

    func encrypt() async {
        errorMessage = nil
        do {
            let resp: EncryptResponse = try await post("/encrypt", body: EncryptRequest(
                plaintext: messageInput,
                aad: "swiftui-client"
            ))
            lastCiphertextHex = resp.ciphertext_hex
            lastKeyId = resp.key_id
            recoveredPlaintext = nil
        } catch {
            errorMessage = "Encrypt failed: \(error.localizedDescription)"
        }
    }

    func decrypt() async {
        guard let ctHex = lastCiphertextHex, let keyId = lastKeyId else {
            errorMessage = "Encrypt a message first"
            return
        }
        errorMessage = nil
        do {
            let resp: DecryptResponse = try await post("/decrypt", body: DecryptRequest(
                ciphertext_hex: ctHex,
                key_id: keyId
            ))
            recoveredPlaintext = resp.plaintext
        } catch {
            errorMessage = "Decrypt failed: \(error.localizedDescription)"
        }
    }

    func rotateKey() async {
        errorMessage = nil
        do {
            let resp: RotationResponse = try await postEmpty("/rotate")
            rotationResult = resp.rotated
                ? "Rotated. New key_id: \(resp.new_key_id)"
                : "Rotation declined"
        } catch {
            errorMessage = "Key rotation failed: \(error.localizedDescription)"
        }
    }

    func runFullDemo(bridge: CryptoLibBridge) async {
        isDemoRunning = true
        demoLog = []
        errorMessage = nil

        func log(_ msg: String) {
            demoLog.append(msg)
        }

        do {
            // Step 1: Check status
            log("[1/6] Checking server status...")
            let status: StatusResponse = try await get("/status")
            log("  Server: \(status.status), v\(status.version)")
            isConnected = true

            // Step 2: Derive identity
            log("[2/6] Deriving Ed25519 identity from file...")
            guard let path = selectedFilePath else {
                log("  ERROR: No entropy file selected")
                isDemoRunning = false
                return
            }
            let handle = try bridge.entropyFromFile(path, deterministic: true)
            let keys = bridge.entropyDeriveAll(handle)
            bridge.entropyFree(handle)
            let kp = bridge.ed25519KeygenFromSeed(keys.signingSeed)
            publicKeyHex = kp.publicKey.hexString
            secretKeyData = kp.secretKey
            log("  Public key: \(kp.publicKey.hexTruncated(16))")

            // Step 3: Enroll
            log("[3/6] Enrolling with server...")
            let enrollResp: EnrollResponse = try await post("/enroll", body: EnrollRequest(pubkey_hex: publicKeyHex!))
            serverFingerprint = enrollResp.server_fingerprint
            log("  Enrolled: \(enrollResp.enrolled), fingerprint: \(enrollResp.server_fingerprint.prefix(32))...")

            // Step 4: Challenge-Response
            log("[4/6] Running challenge-response auth...")
            let challenge: ChallengeResponse = try await get("/challenge?pubkey_hex=\(publicKeyHex!)")
            let challengeData = Data(hexString: challenge.challenge_hex)
            let signature = try bridge.ed25519Sign(challengeData, secretKey: kp.secretKey)
            let verifyReq = VerifyRequest(
                pubkey_hex: publicKeyHex!,
                challenge_hex: challenge.challenge_hex,
                signature_hex: signature.hexString
            )
            let verifyResp: VerifyResponse = try await post("/verify", body: verifyReq)
            challengeResult = verifyResp.verified ? "Verified: \(verifyResp.message)" : "Failed"
            log("  Verified: \(verifyResp.verified) — \(verifyResp.message)")

            // Step 5: Encrypt + Decrypt
            log("[5/6] Encrypt + Decrypt round-trip...")
            let encResp: EncryptResponse = try await post("/encrypt", body: EncryptRequest(
                plaintext: messageInput,
                aad: "swiftui-demo"
            ))
            lastCiphertextHex = encResp.ciphertext_hex
            lastKeyId = encResp.key_id
            log("  Ciphertext: \(encResp.ciphertext_hex.prefix(32))...")
            log("  Key ID: \(encResp.key_id)")

            let decResp: DecryptResponse = try await post("/decrypt", body: DecryptRequest(
                ciphertext_hex: encResp.ciphertext_hex,
                key_id: encResp.key_id
            ))
            recoveredPlaintext = decResp.plaintext
            log("  Decrypted: \(decResp.plaintext)")

            // Step 6: Key Rotation
            log("[6/6] Requesting key rotation...")
            do {
                let rotResp: RotationResponse = try await postEmpty("/rotate")
                rotationResult = "Rotated. New key_id: \(rotResp.new_key_id)"
                log("  Rotated: \(rotResp.rotated), new key_id: \(rotResp.new_key_id)")
            } catch {
                log("  Key rotation not available: \(error.localizedDescription)")
            }

            log("Full demo completed successfully.")
        } catch {
            log("ERROR: \(error.localizedDescription)")
            errorMessage = error.localizedDescription
        }

        isDemoRunning = false
    }
}

// MARK: - Data hex init helper

private extension Data {
    init(hexString: String) {
        self.init()
        var hex = hexString
        while hex.count >= 2 {
            let byteString = String(hex.prefix(2))
            hex = String(hex.dropFirst(2))
            if let byte = UInt8(byteString, radix: 16) {
                self.append(byte)
            }
        }
    }
}

// MARK: - View

struct LavaRandClientView: View {
    let bridge: CryptoLibBridge
    @State private var vm = LavaRandClientViewModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                headerSection
                connectionSection
                identitySection

                if let error = vm.errorMessage {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundColor(.red)
                }

                DisclosureGroup("Enroll") {
                    enrollSection
                }

                DisclosureGroup("Challenge-Response") {
                    challengeSection
                }

                DisclosureGroup("Encrypt") {
                    encryptSection
                }

                DisclosureGroup("Decrypt") {
                    decryptSection
                }

                DisclosureGroup("Key Rotation") {
                    rotationSection
                }

                DisclosureGroup("Full Demo") {
                    fullDemoSection
                }
            }
            .padding()
        }
        .navigationTitle("LavaRand Client")
    }

    // MARK: - Header

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("LavaRand Server Client")
                .font(.title2.bold())
            Text("Connect to a LavaRand HTTP server: enroll, authenticate via challenge-response, encrypt/decrypt messages, and rotate keys.")
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - Connection

    private var connectionSection: some View {
        GroupBox("Connection") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    TextField("Server URL", text: $vm.serverURL)
                        .textFieldStyle(.roundedBorder)

                    Button {
                        Task { await vm.checkStatus() }
                    } label: {
                        Label("Check Status", systemImage: "antenna.radiowaves.left.and.right")
                    }
                    .buttonStyle(.borderedProminent)
                }

                HStack(spacing: 6) {
                    Image(systemName: vm.isConnected ? "circle.fill" : "circle")
                        .foregroundColor(vm.isConnected ? .green : .gray)
                        .font(.caption)
                    Text(vm.isConnected ? "Connected" : "Not connected")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if let info = vm.statusInfo {
                    Text(info)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(6)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                }
            }
            .padding(.vertical, 4)
        }
    }

    // MARK: - Client Identity

    private var identitySection: some View {
        GroupBox("Client Identity") {
            VStack(alignment: .leading, spacing: 10) {
                FilePickerButton("Choose Entropy File",
                                 allowedTypes: ["png", "jpg", "jpeg", "ppm", "wav", "mp3", "mp4", "crvf"]) { url in
                    vm.selectedFilePath = url.path
                    vm.deriveIdentity(bridge: bridge)
                }

                if let pubHex = vm.publicKeyHex {
                    HexStringView(label: "Ed25519 Public Key", hex: pubHex)
                }
            }
            .padding(.vertical, 4)
        }
    }

    // MARK: - Enroll

    private var enrollSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Register your public key with the server. Returns the server's fingerprint.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Button {
                Task { await vm.enroll() }
            } label: {
                Label("Enroll", systemImage: "person.badge.plus")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vm.publicKeyHex == nil || !vm.isConnected)

            if let fp = vm.serverFingerprint {
                HexStringView(label: "Server Fingerprint", hex: fp)
            }
        }
        .padding(.top, 8)
    }

    // MARK: - Challenge-Response

    private var challengeSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Request a challenge from the server, sign it with your Ed25519 key, and verify the signature.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Button {
                Task { await vm.challengeResponse(bridge: bridge) }
            } label: {
                Label("Run Challenge-Response", systemImage: "key")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vm.publicKeyHex == nil || !vm.isConnected)

            if let result = vm.challengeResult {
                Label(result, systemImage: result.hasPrefix("Verified") ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(result.hasPrefix("Verified") ? .green : .red)
                    .font(.body.weight(.semibold))
            }
        }
        .padding(.top, 8)
    }

    // MARK: - Encrypt

    private var encryptSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Encrypt a plaintext message on the server. Returns ciphertext and a key ID.")
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

            Button {
                Task { await vm.encrypt() }
            } label: {
                Label("Encrypt", systemImage: "lock")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!vm.isConnected)

            if let ct = vm.lastCiphertextHex {
                HexStringView(label: "Ciphertext", hex: ct)
            }
            if let keyId = vm.lastKeyId {
                HStack {
                    Text("Key ID:")
                        .font(.subheadline.weight(.semibold))
                    Text(keyId)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
        .padding(.top, 8)
    }

    // MARK: - Decrypt

    private var decryptSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Decrypt the last ciphertext using its key ID.")
                .font(.caption)
                .foregroundStyle(.secondary)

            if let ct = vm.lastCiphertextHex {
                HexStringView(label: "Ciphertext (from Encrypt)", hex: ct)
            }
            if let keyId = vm.lastKeyId {
                HStack {
                    Text("Key ID:")
                        .font(.subheadline.weight(.semibold))
                    Text(keyId)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }

            Button {
                Task { await vm.decrypt() }
            } label: {
                Label("Decrypt", systemImage: "lock.open")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vm.lastCiphertextHex == nil)

            if let pt = vm.recoveredPlaintext {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Recovered Plaintext")
                        .font(.headline)
                    Text(pt)
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

    // MARK: - Key Rotation

    private var rotationSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Request the server to rotate its encryption key.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Button {
                Task { await vm.rotateKey() }
            } label: {
                Label("Rotate Key", systemImage: "arrow.triangle.2.circlepath")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!vm.isConnected)

            if let result = vm.rotationResult {
                Label(result, systemImage: "checkmark.circle.fill")
                    .foregroundColor(.green)
                    .font(.body.weight(.semibold))
            }
        }
        .padding(.top, 8)
    }

    // MARK: - Full Demo

    private var fullDemoSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Run all steps sequentially: status check, identity derivation, enrollment, challenge-response, encrypt/decrypt round-trip, and key rotation.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Button {
                Task { await vm.runFullDemo(bridge: bridge) }
            } label: {
                Label(vm.isDemoRunning ? "Running..." : "Run Full Demo", systemImage: "play.fill")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vm.selectedFilePath == nil || vm.isDemoRunning)

            if !vm.demoLog.isEmpty {
                GroupBox("Demo Log") {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(vm.demoLog.enumerated()), id: \.offset) { _, line in
                                Text(line)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundColor(line.contains("ERROR") ? .red : .primary)
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        .padding(8)
                    }
                    .frame(maxHeight: 300)
                }
            }
        }
        .padding(.top, 8)
    }
}
