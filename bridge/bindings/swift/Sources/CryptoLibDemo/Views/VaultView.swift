import SwiftUI

enum VaultKeySource: String, CaseIterable, Identifiable {
    case entropy = "Entropy File"
    var id: String { rawValue }
}

@Observable
final class VaultViewModel {
    var selectedFilePath: String?
    var plaintext = "Top secret vault payload"
    var aadText = ""
    var masterKey: Data?
    var vaultHandle: UnsafeMutableRawPointer?
    var entropyHandle: UnsafeMutableRawPointer?
    var sealedPacket: PacketResult?
    var recoveredText: String?
    var errorMessage: String?
    var isProcessing = false

    func createVault(bridge: CryptoLibBridge) {
        cleanupHandles(bridge: bridge)
        errorMessage = nil
        sealedPacket = nil
        recoveredText = nil

        do {
            guard let path = selectedFilePath else {
                errorMessage = "Select a file first"
                return
            }
            let eHandle = try bridge.entropyFromFile(path, deterministic: true)
            entropyHandle = eHandle
            vaultHandle = try bridge.vaultFromEntropy(eHandle)
            let dk = bridge.entropyDeriveAll(eHandle)
            masterKey = dk.vaultMasterKey
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func seal(bridge: CryptoLibBridge) {
        guard let vault = vaultHandle else {
            errorMessage = "Create a vault first"
            return
        }
        guard let ptData = plaintext.data(using: .utf8) else {
            errorMessage = "Invalid UTF-8 input"
            return
        }
        errorMessage = nil
        recoveredText = nil
        isProcessing = true

        do {
            sealedPacket = try bridge.vaultSeal(vault, plaintext: ptData, aad: aadText)
        } catch {
            errorMessage = error.localizedDescription
        }
        isProcessing = false
    }

    func open(bridge: CryptoLibBridge) {
        guard let vault = vaultHandle, let packet = sealedPacket else {
            errorMessage = "Seal something first"
            return
        }
        errorMessage = nil
        isProcessing = true

        do {
            let data = try bridge.vaultOpen(vault, packet: packet, aad: aadText)
            recoveredText = String(data: data, encoding: .utf8) ?? data.hexString
        } catch {
            errorMessage = error.localizedDescription
        }
        isProcessing = false
    }

    func cleanupHandles(bridge: CryptoLibBridge) {
        if let v = vaultHandle {
            bridge.vaultFree(v)
            vaultHandle = nil
        }
        if let e = entropyHandle {
            bridge.entropyFree(e)
            entropyHandle = nil
        }
    }
}

struct VaultView: View {
    let bridge: CryptoLibBridge
    @State private var vm = VaultViewModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                headerSection
                keySourceSection
                vaultActions
                plaintextSection
                sealOpenButtons
                resultSection
            }
            .padding()
        }
        .navigationTitle("Vault")
        .onDisappear { vm.cleanupHandles(bridge: bridge) }
    }

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Secure Vault")
                .font(.title2.bold())
            Text("4-layer encryption pipeline: Argon2id KDF, BLAKE2b HMAC, XChaCha20-Poly1305 AEAD, Ed25519 signature.")
                .foregroundStyle(.secondary)
        }
    }

    private var keySourceSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Key Source (Entropy File)")
                .font(.headline)

            FilePickerButton("Choose Entropy File", allowedTypes: ["png", "jpg", "jpeg", "ppm", "wav"]) { url in
                vm.selectedFilePath = url.path
            }
        }
    }

    private var vaultActions: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                vm.createVault(bridge: bridge)
            } label: {
                Label("Create Vault", systemImage: "archivebox")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vm.selectedFilePath == nil)

            if let key = vm.masterKey {
                HexStringView(label: "Master Key", data: key)
            }

            if vm.vaultHandle != nil {
                Label("Vault active", systemImage: "checkmark.circle.fill")
                    .foregroundColor(.green)
                    .font(.caption)
            }
        }
    }

    private var plaintextSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Plaintext")
                .font(.headline)
            TextEditor(text: $vm.plaintext)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 60, maxHeight: 100)
                .padding(4)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.tertiary))

            TextField("AAD (optional)", text: $vm.aadText)
                .textFieldStyle(.roundedBorder)
        }
    }

    private var sealOpenButtons: some View {
        HStack(spacing: 12) {
            Button {
                vm.seal(bridge: bridge)
            } label: {
                Label("Seal", systemImage: "lock")
            }
            .buttonStyle(.borderedProminent)
            .disabled(vm.vaultHandle == nil || vm.isProcessing)

            Button {
                vm.open(bridge: bridge)
            } label: {
                Label("Open", systemImage: "lock.open")
            }
            .buttonStyle(.bordered)
            .disabled(vm.sealedPacket == nil || vm.isProcessing)
        }
    }

    @ViewBuilder
    private var resultSection: some View {
        if vm.isProcessing {
            ProgressView()
        }

        if let error = vm.errorMessage {
            Label(error, systemImage: "exclamationmark.triangle")
                .foregroundColor(.red)
        }

        if let packet = vm.sealedPacket {
            Divider()
            GroupBox("Sealed Packet") {
                VStack(spacing: 10) {
                    HexStringView(label: "Ciphertext (nonce + encrypted + MAC)", data: packet.ciphertext)
                    HexStringView(label: "Ed25519 Signature (64 B)", data: packet.signature)
                    HexStringView(label: "Argon2id KDF Salt (16 B)", data: packet.kdfSalt)
                }
                .padding(.vertical, 4)
            }
        }

        if let recovered = vm.recoveredText {
            Divider()
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
}
