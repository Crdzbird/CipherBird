import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../cryptolib_ffi.dart';
import '../widgets/hex_display.dart';
import '../widgets/result_card.dart';

class AsymmetricPage extends StatefulWidget {
  final CryptoLib lib;

  const AsymmetricPage({super.key, required this.lib});

  @override
  State<AsymmetricPage> createState() => _AsymmetricPageState();
}

class _AsymmetricPageState extends State<AsymmetricPage>
    with AutomaticKeepAliveClientMixin {
  // ── Ed25519 state ──
  final _ed25519MsgController = TextEditingController();
  KeyPairResult? _edKeypair;
  String _edPublicHex = '';
  String _edSignatureHex = '';
  Uint8List? _edSignature;
  String? _edVerifyResult;
  bool? _edVerifyOk;
  String? _edError;

  // ── Box state ──
  final _boxMsgController = TextEditingController();
  KeyPairResult? _aliceBoxKeys;
  KeyPairResult? _bobBoxKeys;
  String _aliceBoxPubHex = '';
  String _bobBoxPubHex = '';
  Uint8List? _boxCiphertext;
  String _boxCiphertextHex = '';
  String _boxDecryptedText = '';
  String? _boxError;

  // ── SealedBox state ──
  final _sealedMsgController = TextEditingController();
  KeyPairResult? _sealedRecipientKeys;
  String _sealedPubHex = '';
  Uint8List? _sealedCiphertext;
  String _sealedCiphertextHex = '';
  String _sealedDecryptedText = '';
  String? _sealedError;

  // ── X25519 state ──
  KeyPairResult? _x25519AliceKeys;
  KeyPairResult? _x25519BobKeys;
  String _x25519AlicePubHex = '';
  String _x25519BobPubHex = '';
  String _x25519AliceSharedHex = '';
  String _x25519BobSharedHex = '';
  bool? _x25519Match;
  String? _x25519Error;

  @override
  bool get wantKeepAlive => true;

  @override
  void dispose() {
    _ed25519MsgController.dispose();
    _boxMsgController.dispose();
    _sealedMsgController.dispose();
    super.dispose();
  }

  // ── Ed25519 actions ──

  void _edGenKeypair() {
    try {
      final kp = widget.lib.ed25519Keygen();
      setState(() {
        _edKeypair = kp;
        _edPublicHex = toHex(kp.publicKey);
        _edSignature = null;
        _edSignatureHex = '';
        _edVerifyResult = null;
        _edVerifyOk = null;
        _edError = null;
      });
    } catch (e) {
      setState(() => _edError = e.toString());
    }
  }

  void _edSign() {
    if (_edKeypair == null) {
      setState(() => _edError = 'Generate a keypair first.');
      return;
    }
    final msgText = _ed25519MsgController.text;
    if (msgText.isEmpty) {
      setState(() => _edError = 'Enter a message to sign.');
      return;
    }
    try {
      final msg = Uint8List.fromList(utf8.encode(msgText));
      final sig = widget.lib.ed25519Sign(msg, _edKeypair!.secretKey);
      setState(() {
        _edSignature = sig;
        _edSignatureHex = toHex(sig);
        _edVerifyResult = null;
        _edVerifyOk = null;
        _edError = null;
      });
    } catch (e) {
      setState(() => _edError = e.toString());
    }
  }

  void _edVerify() {
    if (_edKeypair == null || _edSignature == null) {
      setState(() => _edError = 'Sign a message first.');
      return;
    }
    try {
      final msg = Uint8List.fromList(utf8.encode(_ed25519MsgController.text));
      final ok = widget.lib.ed25519Verify(msg, _edSignature!, _edKeypair!.publicKey);
      setState(() {
        _edVerifyResult = ok ? 'Signature VALID' : 'Signature REJECTED';
        _edVerifyOk = ok;
        _edError = null;
      });
    } catch (e) {
      setState(() => _edError = e.toString());
    }
  }

  void _edTamperAndVerify() {
    if (_edKeypair == null || _edSignature == null) {
      setState(() => _edError = 'Sign a message first.');
      return;
    }
    try {
      final msg = Uint8List.fromList(utf8.encode(_ed25519MsgController.text));
      // Flip a bit in the signature
      final tampered = Uint8List.fromList(_edSignature!);
      tampered[0] ^= 0x01;
      final ok = widget.lib.ed25519Verify(msg, tampered, _edKeypair!.publicKey);
      setState(() {
        _edVerifyResult = ok
            ? 'Tampered signature accepted (unexpected!)'
            : 'Tampered signature REJECTED (expected)';
        _edVerifyOk = ok;
        _edError = null;
      });
    } catch (e) {
      setState(() => _edError = e.toString());
    }
  }

  // ── Box actions ──

  void _boxGenAlice() {
    try {
      final kp = widget.lib.boxKeygen();
      setState(() {
        _aliceBoxKeys = kp;
        _aliceBoxPubHex = toHex(kp.publicKey);
        _boxCiphertext = null;
        _boxCiphertextHex = '';
        _boxDecryptedText = '';
        _boxError = null;
      });
    } catch (e) {
      setState(() => _boxError = e.toString());
    }
  }

  void _boxGenBob() {
    try {
      final kp = widget.lib.boxKeygen();
      setState(() {
        _bobBoxKeys = kp;
        _bobBoxPubHex = toHex(kp.publicKey);
        _boxCiphertext = null;
        _boxCiphertextHex = '';
        _boxDecryptedText = '';
        _boxError = null;
      });
    } catch (e) {
      setState(() => _boxError = e.toString());
    }
  }

  void _boxEncrypt() {
    if (_aliceBoxKeys == null || _bobBoxKeys == null) {
      setState(() => _boxError = 'Generate both Alice and Bob keys first.');
      return;
    }
    final msgText = _boxMsgController.text;
    if (msgText.isEmpty) {
      setState(() => _boxError = 'Enter a message to encrypt.');
      return;
    }
    try {
      final pt = Uint8List.fromList(utf8.encode(msgText));
      final ct = widget.lib.boxEncrypt(pt, _bobBoxKeys!.publicKey, _aliceBoxKeys!.secretKey);
      setState(() {
        _boxCiphertext = ct;
        _boxCiphertextHex = toHex(ct);
        _boxDecryptedText = '';
        _boxError = null;
      });
    } catch (e) {
      setState(() => _boxError = e.toString());
    }
  }

  void _boxDecrypt() {
    if (_aliceBoxKeys == null || _bobBoxKeys == null) {
      setState(() => _boxError = 'No keys available.');
      return;
    }
    if (_boxCiphertext == null) {
      setState(() => _boxError = 'Encrypt something first.');
      return;
    }
    try {
      final pt = widget.lib.boxDecrypt(
        _boxCiphertext!,
        _aliceBoxKeys!.publicKey,
        _bobBoxKeys!.secretKey,
      );
      setState(() {
        _boxDecryptedText = utf8.decode(pt);
        _boxError = null;
      });
    } catch (e) {
      setState(() => _boxError = e.toString());
    }
  }

  // ── SealedBox actions ──

  void _sealedGenKeys() {
    try {
      final kp = widget.lib.boxKeygen();
      setState(() {
        _sealedRecipientKeys = kp;
        _sealedPubHex = toHex(kp.publicKey);
        _sealedCiphertext = null;
        _sealedCiphertextHex = '';
        _sealedDecryptedText = '';
        _sealedError = null;
      });
    } catch (e) {
      setState(() => _sealedError = e.toString());
    }
  }

  void _sealedEncrypt() {
    if (_sealedRecipientKeys == null) {
      setState(() => _sealedError = 'Generate recipient keys first.');
      return;
    }
    final msgText = _sealedMsgController.text;
    if (msgText.isEmpty) {
      setState(() => _sealedError = 'Enter a message to encrypt.');
      return;
    }
    try {
      final pt = Uint8List.fromList(utf8.encode(msgText));
      final ct = widget.lib.sealedboxEncrypt(pt, _sealedRecipientKeys!.publicKey);
      setState(() {
        _sealedCiphertext = ct;
        _sealedCiphertextHex = toHex(ct);
        _sealedDecryptedText = '';
        _sealedError = null;
      });
    } catch (e) {
      setState(() => _sealedError = e.toString());
    }
  }

  void _sealedDecrypt() {
    if (_sealedRecipientKeys == null) {
      setState(() => _sealedError = 'No keys available.');
      return;
    }
    if (_sealedCiphertext == null) {
      setState(() => _sealedError = 'Encrypt something first.');
      return;
    }
    try {
      final pt = widget.lib.sealedboxDecrypt(
        _sealedCiphertext!,
        _sealedRecipientKeys!.publicKey,
        _sealedRecipientKeys!.secretKey,
      );
      setState(() {
        _sealedDecryptedText = utf8.decode(pt);
        _sealedError = null;
      });
    } catch (e) {
      setState(() => _sealedError = e.toString());
    }
  }

  // ── X25519 actions ──

  void _x25519GenAlice() {
    try {
      final kp = widget.lib.x25519Keygen();
      setState(() {
        _x25519AliceKeys = kp;
        _x25519AlicePubHex = toHex(kp.publicKey);
        _x25519AliceSharedHex = '';
        _x25519BobSharedHex = '';
        _x25519Match = null;
        _x25519Error = null;
      });
    } catch (e) {
      setState(() => _x25519Error = e.toString());
    }
  }

  void _x25519GenBob() {
    try {
      final kp = widget.lib.x25519Keygen();
      setState(() {
        _x25519BobKeys = kp;
        _x25519BobPubHex = toHex(kp.publicKey);
        _x25519AliceSharedHex = '';
        _x25519BobSharedHex = '';
        _x25519Match = null;
        _x25519Error = null;
      });
    } catch (e) {
      setState(() => _x25519Error = e.toString());
    }
  }

  void _x25519ComputeShared() {
    if (_x25519AliceKeys == null || _x25519BobKeys == null) {
      setState(() => _x25519Error = 'Generate both Alice and Bob keys first.');
      return;
    }
    try {
      final aliceShared = widget.lib.x25519SharedSecret(
        _x25519AliceKeys!.secretKey,
        _x25519BobKeys!.publicKey,
      );
      final bobShared = widget.lib.x25519SharedSecret(
        _x25519BobKeys!.secretKey,
        _x25519AliceKeys!.publicKey,
      );
      final match = widget.lib.secureEqual(aliceShared, bobShared);
      setState(() {
        _x25519AliceSharedHex = toHex(aliceShared);
        _x25519BobSharedHex = toHex(bobShared);
        _x25519Match = match;
        _x25519Error = null;
      });
    } catch (e) {
      setState(() => _x25519Error = e.toString());
    }
  }

  // ── Build ──

  Widget _sectionHeader(BuildContext context, String title, String subtitle) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Divider(height: 48),
        Text(title, style: theme.textTheme.titleLarge),
        const SizedBox(height: 4),
        Text(
          subtitle,
          style: theme.textTheme.bodyMedium?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 16),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final theme = Theme.of(context);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Asymmetric Cryptography',
            style: theme.textTheme.headlineSmall,
          ),
          const SizedBox(height: 8),
          Text(
            'Ed25519 digital signatures, Box authenticated encryption, '
            'SealedBox anonymous encryption, and X25519 key agreement.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),

          // ════════════════════════════════════════════════════════════════
          // Section A: Ed25519 Signing
          // ════════════════════════════════════════════════════════════════
          _sectionHeader(
            context,
            'Ed25519 Digital Signatures',
            'Generate a keypair, sign a message, then verify or tamper with the signature.',
          ),

          FilledButton.icon(
            onPressed: _edGenKeypair,
            icon: const Icon(Icons.vpn_key, size: 18),
            label: const Text('Generate Keypair'),
          ),
          if (_edPublicHex.isNotEmpty) ...[
            const SizedBox(height: 12),
            HexDisplay(label: 'Ed25519 Public Key (32 B)', hexString: _edPublicHex),
          ],
          const SizedBox(height: 16),

          TextField(
            controller: _ed25519MsgController,
            decoration: const InputDecoration(
              labelText: 'Message',
              hintText: 'Enter text to sign...',
              border: OutlineInputBorder(),
            ),
            maxLines: 2,
          ),
          const SizedBox(height: 16),

          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: _edSign,
                icon: const Icon(Icons.draw, size: 18),
                label: const Text('Sign'),
              ),
              FilledButton.tonalIcon(
                onPressed: _edVerify,
                icon: const Icon(Icons.verified, size: 18),
                label: const Text('Verify'),
              ),
              OutlinedButton.icon(
                onPressed: _edTamperAndVerify,
                icon: const Icon(Icons.bug_report, size: 18),
                label: const Text('Tamper & Verify'),
              ),
            ],
          ),
          const SizedBox(height: 16),

          if (_edError != null) ResultCard.error(_edError!),
          if (_edSignatureHex.isNotEmpty)
            HexDisplay(label: 'Signature (64 B)', hexString: _edSignatureHex),
          if (_edVerifyResult != null) ...[
            const SizedBox(height: 12),
            _edVerifyOk == true
                ? ResultCard.success(_edVerifyResult!)
                : ResultCard.error(_edVerifyResult!),
          ],

          // ════════════════════════════════════════════════════════════════
          // Section B: Box Encryption (Alice -> Bob)
          // ════════════════════════════════════════════════════════════════
          _sectionHeader(
            context,
            'Box Encryption (Alice \u2192 Bob)',
            'Authenticated public-key encryption. Alice encrypts for Bob using '
            "Bob's public key and her secret key.",
          ),

          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: _boxGenAlice,
                icon: const Icon(Icons.person, size: 18),
                label: const Text('Generate Alice Keys'),
              ),
              FilledButton.tonalIcon(
                onPressed: _boxGenBob,
                icon: const Icon(Icons.person_outline, size: 18),
                label: const Text('Generate Bob Keys'),
              ),
            ],
          ),
          if (_aliceBoxPubHex.isNotEmpty) ...[
            const SizedBox(height: 12),
            HexDisplay(label: 'Alice Public Key', hexString: _aliceBoxPubHex),
          ],
          if (_bobBoxPubHex.isNotEmpty) ...[
            const SizedBox(height: 8),
            HexDisplay(label: 'Bob Public Key', hexString: _bobBoxPubHex),
          ],
          const SizedBox(height: 16),

          TextField(
            controller: _boxMsgController,
            decoration: const InputDecoration(
              labelText: 'Message',
              hintText: 'Enter text for Alice to send to Bob...',
              border: OutlineInputBorder(),
            ),
            maxLines: 2,
          ),
          const SizedBox(height: 16),

          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: _boxEncrypt,
                icon: const Icon(Icons.lock, size: 18),
                label: const Text('Alice Encrypts for Bob'),
              ),
              OutlinedButton.icon(
                onPressed: _boxDecrypt,
                icon: const Icon(Icons.lock_open, size: 18),
                label: const Text('Bob Decrypts'),
              ),
            ],
          ),
          const SizedBox(height: 16),

          if (_boxError != null) ResultCard.error(_boxError!),
          if (_boxCiphertextHex.isNotEmpty)
            HexDisplay(label: 'Box Ciphertext', hexString: _boxCiphertextHex),
          if (_boxDecryptedText.isNotEmpty) ...[
            const SizedBox(height: 12),
            ResultCard.success(_boxDecryptedText, title: 'Bob Recovered Plaintext'),
          ],

          // ════════════════════════════════════════════════════════════════
          // Section C: SealedBox (Anonymous Sender)
          // ════════════════════════════════════════════════════════════════
          _sectionHeader(
            context,
            'SealedBox (Anonymous Sender)',
            'Encrypt for a recipient using only their public key. '
            'The sender identity is not authenticated.',
          ),

          FilledButton.icon(
            onPressed: _sealedGenKeys,
            icon: const Icon(Icons.vpn_key, size: 18),
            label: const Text('Generate Recipient Keys'),
          ),
          if (_sealedPubHex.isNotEmpty) ...[
            const SizedBox(height: 12),
            HexDisplay(label: 'Recipient Public Key', hexString: _sealedPubHex),
          ],
          const SizedBox(height: 16),

          TextField(
            controller: _sealedMsgController,
            decoration: const InputDecoration(
              labelText: 'Message',
              hintText: 'Enter anonymous message...',
              border: OutlineInputBorder(),
            ),
            maxLines: 2,
          ),
          const SizedBox(height: 16),

          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: _sealedEncrypt,
                icon: const Icon(Icons.lock, size: 18),
                label: const Text('Encrypt (anonymous)'),
              ),
              OutlinedButton.icon(
                onPressed: _sealedDecrypt,
                icon: const Icon(Icons.lock_open, size: 18),
                label: const Text('Decrypt'),
              ),
            ],
          ),
          const SizedBox(height: 16),

          if (_sealedError != null) ResultCard.error(_sealedError!),
          if (_sealedCiphertextHex.isNotEmpty)
            HexDisplay(label: 'SealedBox Ciphertext', hexString: _sealedCiphertextHex),
          if (_sealedDecryptedText.isNotEmpty) ...[
            const SizedBox(height: 12),
            ResultCard.success(_sealedDecryptedText, title: 'Decrypted Plaintext'),
          ],

          // ════════════════════════════════════════════════════════════════
          // Section D: X25519 Key Agreement
          // ════════════════════════════════════════════════════════════════
          _sectionHeader(
            context,
            'X25519 Key Agreement',
            'Both parties independently compute the same shared secret '
            'from their own secret key and the other party\'s public key.',
          ),

          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: _x25519GenAlice,
                icon: const Icon(Icons.person, size: 18),
                label: const Text('Generate Alice Keys'),
              ),
              FilledButton.tonalIcon(
                onPressed: _x25519GenBob,
                icon: const Icon(Icons.person_outline, size: 18),
                label: const Text('Generate Bob Keys'),
              ),
            ],
          ),
          if (_x25519AlicePubHex.isNotEmpty) ...[
            const SizedBox(height: 12),
            HexDisplay(label: 'Alice Public Key', hexString: _x25519AlicePubHex),
          ],
          if (_x25519BobPubHex.isNotEmpty) ...[
            const SizedBox(height: 8),
            HexDisplay(label: 'Bob Public Key', hexString: _x25519BobPubHex),
          ],
          const SizedBox(height: 16),

          FilledButton.icon(
            onPressed: _x25519ComputeShared,
            icon: const Icon(Icons.handshake, size: 18),
            label: const Text('Compute Shared Secrets'),
          ),
          const SizedBox(height: 16),

          if (_x25519Error != null) ResultCard.error(_x25519Error!),
          if (_x25519AliceSharedHex.isNotEmpty) ...[
            HexDisplay(label: 'Alice\'s Shared Secret', hexString: _x25519AliceSharedHex),
            const SizedBox(height: 8),
            HexDisplay(label: 'Bob\'s Shared Secret', hexString: _x25519BobSharedHex),
            const SizedBox(height: 12),
            if (_x25519Match == true)
              ResultCard.success('Shared secrets are IDENTICAL (key agreement succeeded)')
            else if (_x25519Match == false)
              ResultCard.error('Shared secrets DIFFER (unexpected!)'),
          ],

          const SizedBox(height: 32),
        ],
      ),
    );
  }
}
