import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../cryptolib_ffi.dart';
import '../widgets/hex_display.dart';
import '../widgets/result_card.dart';

enum CipherMode { xchacha20, aes256gcm }

class EncryptionPage extends StatefulWidget {
  final CryptoLib lib;

  const EncryptionPage({super.key, required this.lib});

  @override
  State<EncryptionPage> createState() => _EncryptionPageState();
}

class _EncryptionPageState extends State<EncryptionPage>
    with AutomaticKeepAliveClientMixin {
  final _plaintextController = TextEditingController();
  final _aadController = TextEditingController();

  CipherMode _mode = CipherMode.xchacha20;
  Uint8List? _key;
  Uint8List? _ciphertext;
  String _keyHex = '';
  String _ciphertextHex = '';
  String _decryptedText = '';
  String? _error;
  bool _aesAvailable = false;

  @override
  bool get wantKeepAlive => true;

  @override
  void initState() {
    super.initState();
    try {
      _aesAvailable = widget.lib.aes256gcmAvailable();
    } catch (_) {
      _aesAvailable = false;
    }
  }

  @override
  void dispose() {
    _plaintextController.dispose();
    _aadController.dispose();
    super.dispose();
  }

  Uint8List? _getAad() {
    final aadText = _aadController.text;
    if (aadText.isEmpty) return null;
    return Uint8List.fromList(utf8.encode(aadText));
  }

  void _generateKey() {
    try {
      final key = widget.lib.symKeygen();
      setState(() {
        _key = key;
        _keyHex = toHex(key);
        _ciphertext = null;
        _ciphertextHex = '';
        _decryptedText = '';
        _error = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  void _encrypt() {
    if (_key == null) {
      setState(() => _error = 'Generate a key first.');
      return;
    }
    final ptText = _plaintextController.text;
    if (ptText.isEmpty) {
      setState(() => _error = 'Enter plaintext to encrypt.');
      return;
    }

    try {
      final pt = Uint8List.fromList(utf8.encode(ptText));
      final aad = _getAad();
      Uint8List ct;

      switch (_mode) {
        case CipherMode.xchacha20:
          ct = widget.lib.xchacha20Encrypt(pt, _key!, aad);
          break;
        case CipherMode.aes256gcm:
          ct = widget.lib.aes256gcmEncrypt(pt, _key!, aad);
          break;
      }

      setState(() {
        _ciphertext = ct;
        _ciphertextHex = toHex(ct);
        _decryptedText = '';
        _error = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  void _decrypt() {
    if (_key == null) {
      setState(() => _error = 'No key available.');
      return;
    }
    if (_ciphertext == null) {
      setState(() => _error = 'Nothing to decrypt. Encrypt something first.');
      return;
    }

    try {
      final aad = _getAad();
      Uint8List pt;

      switch (_mode) {
        case CipherMode.xchacha20:
          pt = widget.lib.xchacha20Decrypt(_ciphertext!, _key!, aad);
          break;
        case CipherMode.aes256gcm:
          pt = widget.lib.aes256gcmDecrypt(_ciphertext!, _key!, aad);
          break;
      }

      setState(() {
        _decryptedText = utf8.decode(pt);
        _error = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final modeName = _mode == CipherMode.xchacha20
        ? 'XChaCha20-Poly1305'
        : 'AES-256-GCM';

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Symmetric AEAD Encryption',
            style: Theme.of(context).textTheme.headlineSmall,
          ),
          const SizedBox(height: 8),
          Text(
            'Authenticated encryption with associated data. '
            'Generate a key, encrypt plaintext, then decrypt to verify.',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
          ),
          const SizedBox(height: 24),

          // Cipher mode selector
          SegmentedButton<CipherMode>(
            segments: [
              const ButtonSegment(
                value: CipherMode.xchacha20,
                label: Text('XChaCha20-Poly1305'),
                icon: Icon(Icons.shield),
              ),
              ButtonSegment(
                value: CipherMode.aes256gcm,
                label: const Text('AES-256-GCM'),
                icon: const Icon(Icons.shield_outlined),
                enabled: _aesAvailable,
              ),
            ],
            selected: {_mode},
            onSelectionChanged: (selected) {
              setState(() {
                _mode = selected.first;
                _ciphertext = null;
                _ciphertextHex = '';
                _decryptedText = '';
              });
            },
          ),
          if (!_aesAvailable)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(
                'AES-256-GCM is not available on this CPU.',
                style: TextStyle(
                  color: Theme.of(context).colorScheme.error,
                  fontSize: 12,
                ),
              ),
            ),
          const SizedBox(height: 24),

          // Key generation
          Row(
            children: [
              FilledButton.icon(
                onPressed: _generateKey,
                icon: const Icon(Icons.vpn_key, size: 18),
                label: const Text('Generate Key'),
              ),
              const SizedBox(width: 16),
              if (_keyHex.isNotEmpty)
                Text(
                  '32-byte key ready',
                  style: TextStyle(
                    color: Colors.green.shade700,
                    fontWeight: FontWeight.w500,
                  ),
                ),
            ],
          ),
          if (_keyHex.isNotEmpty) ...[
            const SizedBox(height: 12),
            HexDisplay(label: 'Symmetric Key', hexString: _keyHex),
          ],

          const SizedBox(height: 24),

          // Plaintext input
          TextField(
            controller: _plaintextController,
            decoration: const InputDecoration(
              labelText: 'Plaintext',
              hintText: 'Enter text to encrypt...',
              border: OutlineInputBorder(),
            ),
            maxLines: 3,
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _aadController,
            decoration: const InputDecoration(
              labelText: 'Additional Authenticated Data (optional)',
              hintText: 'e.g. context, metadata...',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 20),

          // Encrypt / Decrypt buttons
          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: _encrypt,
                icon: const Icon(Icons.lock, size: 18),
                label: Text('Encrypt ($modeName)'),
              ),
              OutlinedButton.icon(
                onPressed: _decrypt,
                icon: const Icon(Icons.lock_open, size: 18),
                label: const Text('Decrypt'),
              ),
            ],
          ),
          const SizedBox(height: 24),

          if (_error != null) ResultCard.error(_error!),

          if (_ciphertextHex.isNotEmpty) ...[
            HexDisplay(label: 'Ciphertext', hexString: _ciphertextHex),
            const SizedBox(height: 16),
          ],

          if (_decryptedText.isNotEmpty)
            ResultCard.success(
              _decryptedText,
              title: 'Decrypted Plaintext',
            ),
        ],
      ),
    );
  }
}
