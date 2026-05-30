import SwiftUI

@Observable
final class HashingViewModel {
    var inputText = "Hello, CryptoLib!"
    var keyText = ""
    var useKey = false
    var resultData: Data?
    var resultLabel = ""
    var errorMessage: String?
    var isProcessing = false

    // HMAC verify state
    var lastHmacKey: Data?
    var lastHmacMac: Data?
    var hmacVerifyResult: String?

    // Argon2id verify state
    var lastPhcStr: String?
    var argonVerifyResult: String?

    func hash(algorithm: String, bridge: CryptoLibBridge) {
        isProcessing = true
        errorMessage = nil
        resultData = nil

        guard let msgData = inputText.data(using: .utf8) else {
            errorMessage = "Invalid UTF-8 input"
            isProcessing = false
            return
        }

        do {
            let keyData = useKey ? keyText.data(using: .utf8) : nil

            switch algorithm {
            case "BLAKE2b":
                resultData = try bridge.blake2b(msgData, key: keyData)
                resultLabel = "BLAKE2b-512"
            case "SHA-256":
                resultData = try bridge.sha256(msgData)
                resultLabel = "SHA-256"
            case "SHA-512":
                resultData = try bridge.sha512(msgData)
                resultLabel = "SHA-512"
            case "HMAC-SHA512":
                let key: Data
                if let keyData, !keyData.isEmpty {
                    key = keyData
                } else {
                    key = try bridge.randomBytes(32)
                }
                let mac = try bridge.hmacSha512(msgData, key: key)
                resultData = mac
                resultLabel = "HMAC-SHA512"
                lastHmacKey = key
                lastHmacMac = mac
                hmacVerifyResult = nil
            case "Argon2id":
                let phcStr = try bridge.argon2idHashStr(inputText)
                resultData = phcStr.data(using: .utf8) ?? Data()
                resultLabel = "Argon2id PHC"
                lastPhcStr = phcStr
                argonVerifyResult = nil
            default:
                errorMessage = "Unknown algorithm"
            }
        } catch {
            errorMessage = error.localizedDescription
        }

        isProcessing = false
    }
}

struct HashingView: View {
    let bridge: CryptoLibBridge
    @State private var vm = HashingViewModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                headerSection
                inputSection
                keySection
                algorithmButtons
                resultSection
            }
            .padding()
        }
        .navigationTitle("Hashing")
    }

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Cryptographic Hashing")
                .font(.title2.bold())
            Text("Compute BLAKE2b, SHA-256, SHA-512, HMAC-SHA512, or Argon2id hashes of your input.")
                .foregroundStyle(.secondary)
        }
    }

    private var inputSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Message")
                .font(.headline)
            TextEditor(text: $vm.inputText)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 80, maxHeight: 160)
                .padding(4)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.tertiary))
        }
    }

    private var keySection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Toggle("Use key (for BLAKE2b / HMAC)", isOn: $vm.useKey)
            if vm.useKey {
                TextField("Key (UTF-8 text)", text: $vm.keyText)
                    .textFieldStyle(.roundedBorder)
            }
        }
    }

    private var algorithmButtons: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Algorithm")
                .font(.headline)
            HStack(spacing: 10) {
                ForEach(["BLAKE2b", "SHA-256", "SHA-512", "HMAC-SHA512", "Argon2id"], id: \.self) { algo in
                    Button(algo) {
                        vm.hash(algorithm: algo, bridge: bridge)
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.isProcessing)
                }
            }
        }
    }

    @ViewBuilder
    private var resultSection: some View {
        if vm.isProcessing {
            ProgressView("Hashing...")
        }

        if let error = vm.errorMessage {
            Label(error, systemImage: "exclamationmark.triangle")
                .foregroundColor(.red)
        }

        if let data = vm.resultData {
            Divider()
            HexView(label: vm.resultLabel, data: data)

            // HMAC verify section
            if vm.resultLabel == "HMAC-SHA512", let _ = vm.lastHmacMac {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Verify HMAC").font(.headline)
                    HStack(spacing: 10) {
                        Button("Verify (correct)") { verifyHmac(tamper: false) }
                            .buttonStyle(.bordered)
                        Button("Tamper & Verify") { verifyHmac(tamper: true) }
                            .buttonStyle(.bordered)
                            .tint(.orange)
                    }
                    if let result = vm.hmacVerifyResult {
                        Text(result)
                            .font(.body.monospaced())
                            .foregroundColor(result.contains("✓") ? .green : .red)
                    }
                }
            }

            // Argon2id verify section
            if vm.resultLabel == "Argon2id PHC", let str = String(data: data, encoding: .utf8) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("PHC String")
                        .font(.headline)
                    Text(str)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary)
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text("Verify Password").font(.headline)
                    HStack(spacing: 10) {
                        Button("Verify (correct)") { verifyArgon2id(wrong: false) }
                            .buttonStyle(.bordered)
                        Button("Verify (wrong password)") { verifyArgon2id(wrong: true) }
                            .buttonStyle(.bordered)
                            .tint(.orange)
                    }
                    if let result = vm.argonVerifyResult {
                        Text(result)
                            .font(.body.monospaced())
                            .foregroundColor(result.contains("✓") ? .green : .red)
                    }
                }
            }
        }
    }

    private func verifyHmac(tamper: Bool) {
        guard let msgData = vm.inputText.data(using: .utf8),
              let key = vm.lastHmacKey,
              var mac = vm.lastHmacMac else { return }
        if tamper {
            var bytes = [UInt8](mac)
            bytes[0] ^= 0xFF
            mac = Data(bytes)
        }
        let ok = bridge.hmacSha512Verify(msgData, mac: mac, key: key)
        vm.hmacVerifyResult = tamper
            ? (ok ? "✗ Tampered MAC accepted (BUG)" : "✓ Tampered MAC rejected")
            : (ok ? "✓ HMAC verified" : "✗ HMAC verification failed")
    }

    private func verifyArgon2id(wrong: Bool) {
        guard let phc = vm.lastPhcStr else { return }
        let password = wrong ? "wrong_password_12345" : vm.inputText
        let ok = bridge.argon2idVerifyStr(password, phcStr: phc)
        vm.argonVerifyResult = wrong
            ? (ok ? "✗ Wrong password accepted (BUG)" : "✓ Wrong password rejected")
            : (ok ? "✓ Password verified" : "✗ Password verification failed")
    }
}
