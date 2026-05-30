import SwiftUI

struct AsymmetricView: View {
    let bridge: CryptoLibBridge

    // Ed25519
    @State private var signMessage = "I, the undersigned, approve this document."
    @State private var signKeypair: KeyPairResult?
    @State private var signature: Data?
    @State private var verifyResult: String?

    // Box
    @State private var boxMessage = "Hello Bob, from Alice!"
    @State private var aliceBox: KeyPairResult?
    @State private var bobBox: KeyPairResult?
    @State private var boxCiphertext: Data?
    @State private var boxDecrypted: String?

    // SealedBox
    @State private var sealedMessage = "Anonymous tip: check the logs."
    @State private var sealedRecipient: KeyPairResult?
    @State private var sealedCiphertext: Data?
    @State private var sealedDecrypted: String?

    // X25519
    @State private var x25519Alice: KeyPairResult?
    @State private var x25519Bob: KeyPairResult?
    @State private var sharedSecretAlice: Data?
    @State private var sharedSecretBob: Data?

    @State private var errorMessage: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                Text("Asymmetric Cryptography")
                    .font(.title2.bold())
                Text("Ed25519 signing, Box encryption, SealedBox, and X25519 key agreement.")
                    .foregroundColor(.secondary)

                Divider()
                ed25519Section
                Divider()
                boxSection
                Divider()
                sealedBoxSection
                Divider()
                x25519Section

                if let err = errorMessage {
                    Text(err).foregroundColor(.red).font(.caption)
                }
            }
            .padding(24)
        }
    }

    // MARK: - Ed25519

    @ViewBuilder
    private var ed25519Section: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Ed25519 — Sign & Verify", systemImage: "signature")
                .font(.headline)

            TextField("Message to sign", text: $signMessage, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(2)

            HStack(spacing: 12) {
                Button("Generate Keypair") {
                    signKeypair = bridge.ed25519Keygen()
                    signature = nil
                    verifyResult = nil
                }
                Button("Sign") { signDocument() }
                    .disabled(signKeypair == nil)
                Button("Verify") { verifySignature(tamper: false) }
                    .disabled(signature == nil)
                Button("Tamper & Verify") { verifySignature(tamper: true) }
                    .disabled(signature == nil)
                    .foregroundColor(.orange)
            }

            if let kp = signKeypair {
                HexView(label: "Public Key", data: kp.publicKey)
            }
            if let sig = signature {
                HexView(label: "Signature (64 B)", data: sig)
            }
            if let result = verifyResult {
                Text(result)
                    .font(.body.monospaced())
                    .foregroundColor(result.contains("✓") ? .green : .red)
            }
        }
    }

    private func signDocument() {
        guard let kp = signKeypair else { return }
        do {
            let msg = Data(signMessage.utf8)
            signature = try bridge.ed25519Sign(msg, secretKey: kp.secretKey)
            verifyResult = nil
        } catch { errorMessage = error.localizedDescription }
    }

    private func verifySignature(tamper: Bool) {
        guard let kp = signKeypair, var sig = signature else { return }
        let msg = Data(signMessage.utf8)
        if tamper {
            var bytes = [UInt8](sig)
            bytes[0] ^= 0xFF
            sig = Data(bytes)
        }
        let ok = bridge.ed25519Verify(msg, sig: sig, publicKey: kp.publicKey)
        verifyResult = tamper
            ? (ok ? "✗ Tampered signature accepted (BUG)" : "✓ Tampered signature rejected")
            : (ok ? "✓ Signature verified" : "✗ Signature verification failed")
    }

    // MARK: - Box

    @ViewBuilder
    private var boxSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Box — Authenticated Encryption (Alice → Bob)", systemImage: "envelope.badge.shield.half.filled")
                .font(.headline)

            TextField("Message", text: $boxMessage, axis: .vertical)
                .textFieldStyle(.roundedBorder)

            HStack(spacing: 12) {
                Button("Generate Alice Keys") {
                    aliceBox = bridge.boxKeygen()
                    boxCiphertext = nil; boxDecrypted = nil
                }
                Button("Generate Bob Keys") {
                    bobBox = bridge.boxKeygen()
                    boxCiphertext = nil; boxDecrypted = nil
                }
                Button("Alice Encrypts for Bob") { boxEncrypt() }
                    .disabled(aliceBox == nil || bobBox == nil)
                Button("Bob Decrypts") { boxDecrypt() }
                    .disabled(boxCiphertext == nil)
            }

            if let a = aliceBox { HexView(label: "Alice Public", data: a.publicKey) }
            if let b = bobBox { HexView(label: "Bob Public", data: b.publicKey) }
            if let ct = boxCiphertext { HexView(label: "Ciphertext", data: ct) }
            if let pt = boxDecrypted {
                Text("Bob received: \(pt)")
                    .font(.body.monospaced())
                    .foregroundColor(.green)
            }
        }
    }

    private func boxEncrypt() {
        guard let alice = aliceBox, let bob = bobBox else { return }
        do {
            boxCiphertext = try bridge.boxEncrypt(Data(boxMessage.utf8),
                recipientPub: bob.publicKey, senderSec: alice.secretKey)
            boxDecrypted = nil
        } catch { errorMessage = error.localizedDescription }
    }

    private func boxDecrypt() {
        guard let alice = aliceBox, let bob = bobBox, let ct = boxCiphertext else { return }
        do {
            let pt = try bridge.boxDecrypt(ct, senderPub: alice.publicKey, recipientSec: bob.secretKey)
            boxDecrypted = String(data: pt, encoding: .utf8) ?? "(binary)"
        } catch { errorMessage = error.localizedDescription }
    }

    // MARK: - SealedBox

    @ViewBuilder
    private var sealedBoxSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("SealedBox — Anonymous Sender", systemImage: "eye.slash")
                .font(.headline)
            Text("The recipient cannot identify the sender.")
                .font(.caption).foregroundColor(.secondary)

            TextField("Message", text: $sealedMessage, axis: .vertical)
                .textFieldStyle(.roundedBorder)

            HStack(spacing: 12) {
                Button("Generate Recipient Keys") {
                    sealedRecipient = bridge.boxKeygen()
                    sealedCiphertext = nil; sealedDecrypted = nil
                }
                Button("Encrypt (anonymous)") { sealedEncrypt() }
                    .disabled(sealedRecipient == nil)
                Button("Decrypt") { sealedDecryptAction() }
                    .disabled(sealedCiphertext == nil)
            }

            if let r = sealedRecipient { HexView(label: "Recipient Public", data: r.publicKey) }
            if let ct = sealedCiphertext { HexView(label: "Ciphertext", data: ct) }
            if let pt = sealedDecrypted {
                Text("Decrypted: \(pt)")
                    .font(.body.monospaced())
                    .foregroundColor(.green)
            }
        }
    }

    private func sealedEncrypt() {
        guard let r = sealedRecipient else { return }
        do {
            sealedCiphertext = try bridge.sealedboxEncrypt(Data(sealedMessage.utf8), recipientPub: r.publicKey)
            sealedDecrypted = nil
        } catch { errorMessage = error.localizedDescription }
    }

    private func sealedDecryptAction() {
        guard let r = sealedRecipient, let ct = sealedCiphertext else { return }
        do {
            let pt = try bridge.sealedboxDecrypt(ct, recipientPub: r.publicKey, recipientSec: r.secretKey)
            sealedDecrypted = String(data: pt, encoding: .utf8) ?? "(binary)"
        } catch { errorMessage = error.localizedDescription }
    }

    // MARK: - X25519

    @ViewBuilder
    private var x25519Section: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("X25519 — Key Agreement", systemImage: "arrow.triangle.2.circlepath")
                .font(.headline)
            Text("Two parties independently derive the same shared secret.")
                .font(.caption).foregroundColor(.secondary)

            HStack(spacing: 12) {
                Button("Generate Alice Keys") {
                    x25519Alice = bridge.x25519Keygen()
                    sharedSecretAlice = nil; sharedSecretBob = nil
                }
                Button("Generate Bob Keys") {
                    x25519Bob = bridge.x25519Keygen()
                    sharedSecretAlice = nil; sharedSecretBob = nil
                }
                Button("Compute Shared Secrets") { computeSharedSecrets() }
                    .disabled(x25519Alice == nil || x25519Bob == nil)
            }

            if let a = x25519Alice { HexView(label: "Alice Public", data: a.publicKey) }
            if let b = x25519Bob { HexView(label: "Bob Public", data: b.publicKey) }
            if let sa = sharedSecretAlice { HexView(label: "Alice's Shared Secret", data: sa) }
            if let sb = sharedSecretBob { HexView(label: "Bob's Shared Secret", data: sb) }
            if let sa = sharedSecretAlice, let sb = sharedSecretBob {
                Text(sa == sb ? "✓ Shared secrets match — key agreement succeeded" : "✗ Secrets differ (BUG)")
                    .font(.body.monospaced())
                    .foregroundColor(sa == sb ? .green : .red)
            }
        }
    }

    private func computeSharedSecrets() {
        guard let alice = x25519Alice, let bob = x25519Bob else { return }
        do {
            sharedSecretAlice = try bridge.x25519SharedSecret(ourSecret: alice.secretKey, theirPublic: bob.publicKey)
            sharedSecretBob = try bridge.x25519SharedSecret(ourSecret: bob.secretKey, theirPublic: alice.publicKey)
        } catch { errorMessage = error.localizedDescription }
    }
}
