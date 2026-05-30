import SwiftUI

enum CipherAlgorithm: String, CaseIterable, Identifiable {
    case xchacha20 = "XChaCha20-Poly1305"
    case aes256gcm = "AES-256-GCM"
    var id: String { rawValue }
}

@Observable
final class EncryptionViewModel {
    var algorithm: CipherAlgorithm = .xchacha20
    var plaintext = "Secret message for encryption"
    var aadText = ""
    var key: Data?
    var ciphertext: Data?
    var decryptedText: String?
    var errorMessage: String?
    var isProcessing = false
    var aesAvailable = true

    func generateKey(bridge: CryptoLibBridge) {
        do {
            key = try bridge.symKeygen()
            ciphertext = nil
            decryptedText = nil
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func encrypt(bridge: CryptoLibBridge) {
        guard let key else {
            errorMessage = "Generate a key first"
            return
        }
        guard let ptData = plaintext.data(using: .utf8) else {
            errorMessage = "Invalid UTF-8 input"
            return
        }
        let aad = aadText.data(using: .utf8) ?? Data()
        errorMessage = nil
        isProcessing = true
        decryptedText = nil

        do {
            switch algorithm {
            case .xchacha20:
                ciphertext = try bridge.xchacha20Encrypt(ptData, key: key, aad: aad)
            case .aes256gcm:
                ciphertext = try bridge.aes256gcmEncrypt(ptData, key: key, aad: aad)
            }
        } catch {
            errorMessage = error.localizedDescription
        }
        isProcessing = false
    }

    func decrypt(bridge: CryptoLibBridge) {
        guard let key else {
            errorMessage = "No key available"
            return
        }
        guard let ciphertext else {
            errorMessage = "No ciphertext to decrypt"
            return
        }
        let aad = aadText.data(using: .utf8) ?? Data()
        errorMessage = nil
        isProcessing = true

        do {
            let ptData: Data
            switch algorithm {
            case .xchacha20:
                ptData = try bridge.xchacha20Decrypt(ciphertext, key: key, aad: aad)
            case .aes256gcm:
                ptData = try bridge.aes256gcmDecrypt(ciphertext, key: key, aad: aad)
            }
            decryptedText = String(data: ptData, encoding: .utf8) ?? ptData.hexString
        } catch {
            errorMessage = error.localizedDescription
        }
        isProcessing = false
    }

    func checkAes(bridge: CryptoLibBridge) {
        aesAvailable = bridge.aes256gcmAvailable()
    }
}

struct EncryptionView: View {
    let bridge: CryptoLibBridge
    @State private var vm = EncryptionViewModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                headerSection
                algorithmPicker
                keySection
                plaintextSection
                aadSection
                actionButtons
                resultsSection
            }
            .padding()
        }
        .navigationTitle("Encryption")
        .onAppear { vm.checkAes(bridge: bridge) }
    }

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Symmetric AEAD Encryption")
                .font(.title2.bold())
            Text("Encrypt and decrypt messages using XChaCha20-Poly1305 or AES-256-GCM.")
                .foregroundStyle(.secondary)
        }
    }

    private var algorithmPicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Algorithm")
                .font(.headline)
            Picker("Algorithm", selection: $vm.algorithm) {
                ForEach(CipherAlgorithm.allCases) { algo in
                    Text(algo.rawValue).tag(algo)
                }
            }
            .pickerStyle(.segmented)

            if vm.algorithm == .aes256gcm && !vm.aesAvailable {
                Label("AES-256-GCM not available on this CPU", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .font(.caption)
            }
        }
    }

    private var keySection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Encryption Key")
                    .font(.headline)
                Spacer()
                Button("Generate Key") {
                    vm.generateKey(bridge: bridge)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }

            if let key = vm.key {
                HexStringView(label: "Key", data: key)
            } else {
                Text("No key generated yet")
                    .foregroundStyle(.secondary)
                    .italic()
            }
        }
    }

    private var plaintextSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Plaintext")
                .font(.headline)
            TextEditor(text: $vm.plaintext)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 60, maxHeight: 120)
                .padding(4)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.tertiary))
        }
    }

    private var aadSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Additional Authenticated Data (AAD)")
                .font(.headline)
            TextField("Optional AAD", text: $vm.aadText)
                .textFieldStyle(.roundedBorder)
            Text("AAD is authenticated but not encrypted.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var actionButtons: some View {
        HStack(spacing: 12) {
            Button {
                vm.encrypt(bridge: bridge)
            } label: {
                Label("Encrypt", systemImage: "lock")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vm.key == nil || vm.isProcessing)

            Button {
                vm.decrypt(bridge: bridge)
            } label: {
                Label("Decrypt", systemImage: "lock.open")
            }
            .buttonStyle(.bordered)
            .disabled(vm.key == nil || vm.ciphertext == nil || vm.isProcessing)
        }
    }

    @ViewBuilder
    private var resultsSection: some View {
        if vm.isProcessing {
            ProgressView()
        }

        if let error = vm.errorMessage {
            Label(error, systemImage: "exclamationmark.triangle")
                .foregroundColor(.red)
        }

        if let ct = vm.ciphertext {
            Divider()
            HexView(label: "Ciphertext", data: ct)
        }

        if let pt = vm.decryptedText {
            Divider()
            VStack(alignment: .leading, spacing: 6) {
                Text("Decrypted Plaintext")
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
}
