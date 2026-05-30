import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import '../cryptolib_ffi.dart';
import '../widgets/hex_display.dart';
import '../widgets/result_card.dart';

enum VaultSource { randomKey, entropyFile }

class VaultPage extends StatefulWidget {
  final CryptoLib lib;

  const VaultPage({super.key, required this.lib});

  @override
  State<VaultPage> createState() => _VaultPageState();
}

class _VaultPageState extends State<VaultPage>
    with AutomaticKeepAliveClientMixin {
  final _plaintextController = TextEditingController();
  final _aadController = TextEditingController();

  VaultSource _source = VaultSource.randomKey;
  String? _filePath;

  Pointer<Void>? _vaultHandle;
  Pointer<Void>? _entropyHandle;
  String _masterKeyHex = '';
  String _publicKeyHex = '';

  Packet? _sealedPacket;
  String _ciphertextHex = '';
  String _signatureHex = '';
  String _saltHex = '';
  String _decryptedText = '';
  String? _error;

  // ── Entropy boost (two-factor) state ──
  bool _boostEnabled = false;
  String? _boostFilePath;
  Pointer<Void>? _boostHandle;
  String? _boostError;
  String _boostStatus = '';

  @override
  bool get wantKeepAlive => true;

  @override
  void dispose() {
    _freeHandles();
    _plaintextController.dispose();
    _aadController.dispose();
    super.dispose();
  }

  void _freeHandles() {
    if (_vaultHandle != null) {
      widget.lib.vaultFree(_vaultHandle!);
      _vaultHandle = null;
    }
    if (_entropyHandle != null) {
      widget.lib.entropyFree(_entropyHandle!);
      _entropyHandle = null;
    }
    if (_boostHandle != null) {
      widget.lib.entropyFree(_boostHandle!);
      _boostHandle = null;
    }
  }

  Future<void> _pickFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select entropy source file',
    );
    if (result != null && result.files.single.path != null) {
      setState(() {
        _filePath = result.files.single.path;
      });
    }
  }

  Future<void> _pickBoostFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select entropy boost file (two-factor)',
    );
    if (result != null && result.files.single.path != null) {
      // Free old boost handle if any
      if (_boostHandle != null) {
        widget.lib.entropyFree(_boostHandle!);
        _boostHandle = null;
      }
      try {
        _boostHandle = widget.lib.entropyFromFileDeterministic(result.files.single.path!);
        setState(() {
          _boostFilePath = result.files.single.path;
          _boostError = null;
          _boostStatus = 'Boost file loaded';
        });
      } catch (e) {
        setState(() {
          _boostError = e.toString();
          _boostFilePath = null;
        });
      }
    }
  }

  void _createVault() {
    _freeHandles();
    _sealedPacket = null;
    _ciphertextHex = '';
    _signatureHex = '';
    _saltHex = '';
    _decryptedText = '';

    try {
      if (_source == VaultSource.randomKey) {
        final masterKey = widget.lib.symKeygen();
        _masterKeyHex = toHex(masterKey);
        _vaultHandle = widget.lib.vaultCreate(masterKey, kdfPreset: 0);
      } else {
        if (_filePath == null) {
          setState(() => _error = 'Select a file first.');
          return;
        }
        _entropyHandle = widget.lib.entropyFromFileDeterministic(_filePath!);
        _masterKeyHex = '(derived from file)';
        _vaultHandle = widget.lib.vaultFromEntropy(_entropyHandle!, kdf: 0);
      }

      final pubKey = widget.lib.vaultPublicKey(_vaultHandle!);
      _publicKeyHex = toHex(pubKey);

      setState(() {
        _error = null;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _vaultHandle = null;
      });
    }
  }

  void _seal() {
    if (_vaultHandle == null) {
      setState(() => _error = 'Create a vault first.');
      return;
    }
    final ptText = _plaintextController.text;
    if (ptText.isEmpty) {
      setState(() => _error = 'Enter plaintext to seal.');
      return;
    }

    if (_boostEnabled && _boostHandle == null) {
      setState(() => _error = 'Entropy boost is enabled but no boost file is loaded. Select a file first.');
      return;
    }

    try {
      final pt = Uint8List.fromList(utf8.encode(ptText));
      final aad = _aadController.text.isEmpty ? 'flutter:vault' : _aadController.text;

      final Packet pkt;
      if (_boostEnabled && _boostHandle != null) {
        pkt = widget.lib.vaultSealBoosted(_vaultHandle!, pt, aad, _boostHandle!);
      } else {
        pkt = widget.lib.vaultSeal(_vaultHandle!, pt, aad);
      }

      setState(() {
        _sealedPacket = pkt;
        _ciphertextHex = toHex(pkt.ciphertext);
        _signatureHex = toHex(pkt.signature);
        _saltHex = toHex(pkt.kdfSalt);
        _decryptedText = '';
        _error = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  void _open() {
    if (_vaultHandle == null) {
      setState(() => _error = 'No vault available.');
      return;
    }
    if (_sealedPacket == null) {
      setState(() => _error = 'Seal something first.');
      return;
    }

    if (_boostEnabled && _boostHandle == null) {
      setState(() => _error = 'Entropy boost is enabled but no boost file is loaded. Select a file first.');
      return;
    }

    try {
      final aad = _aadController.text.isEmpty ? 'flutter:vault' : _aadController.text;

      final Uint8List pt;
      if (_boostEnabled && _boostHandle != null) {
        pt = widget.lib.vaultOpenBoosted(_vaultHandle!, _sealedPacket!, aad, _boostHandle!);
      } else {
        pt = widget.lib.vaultOpen(_vaultHandle!, _sealedPacket!, aad);
      }

      setState(() {
        _decryptedText = utf8.decode(pt);
        _error = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  void _openWithoutBoost() {
    if (_vaultHandle == null) {
      setState(() => _error = 'No vault available.');
      return;
    }
    if (_sealedPacket == null) {
      setState(() => _error = 'Seal something first.');
      return;
    }

    try {
      final aad = _aadController.text.isEmpty ? 'flutter:vault' : _aadController.text;
      // Attempt to open WITHOUT boost, even though it was sealed WITH boost
      final pt = widget.lib.vaultOpen(_vaultHandle!, _sealedPacket!, aad);
      setState(() {
        _decryptedText = utf8.decode(pt);
        _boostError = 'Opened WITHOUT boost (unexpected - boost should be required)';
        _error = null;
      });
    } catch (e) {
      setState(() {
        _boostError = null;
        _boostStatus = 'Opening WITHOUT boost file FAILED (expected). The boost file is required.';
        _error = e.toString();
      });
    }
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
            'Secure Vault',
            style: theme.textTheme.headlineSmall,
          ),
          const SizedBox(height: 8),
          Text(
            '4-layer pipeline: Argon2id KDF, BLAKE2b HMAC, XChaCha20-Poly1305 AEAD, Ed25519 signature. '
            'Choose a random master key or derive one from a media file.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 24),

          // Source selector
          SegmentedButton<VaultSource>(
            segments: const [
              ButtonSegment(
                value: VaultSource.randomKey,
                label: Text('Random Master Key'),
                icon: Icon(Icons.casino),
              ),
              ButtonSegment(
                value: VaultSource.entropyFile,
                label: Text('From Entropy File'),
                icon: Icon(Icons.photo_camera),
              ),
            ],
            selected: {_source},
            onSelectionChanged: (selected) {
              setState(() => _source = selected.first);
            },
          ),
          const SizedBox(height: 16),

          // File picker (only for entropy source)
          if (_source == VaultSource.entropyFile) ...[
            Row(
              children: [
                OutlinedButton.icon(
                  onPressed: _pickFile,
                  icon: const Icon(Icons.folder_open, size: 18),
                  label: const Text('Select File'),
                ),
                const SizedBox(width: 16),
                if (_filePath != null)
                  Expanded(
                    child: Text(
                      _filePath!,
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 16),
          ],

          FilledButton.icon(
            onPressed: _createVault,
            icon: const Icon(Icons.security, size: 18),
            label: const Text('Create Vault'),
          ),
          const SizedBox(height: 16),

          if (_error != null) ResultCard.error(_error!),

          // Vault info
          if (_vaultHandle != null) ...[
            HexDisplay(label: 'Master Key', hexString: _masterKeyHex),
            const SizedBox(height: 12),
            HexDisplay(
              label: 'Ed25519 Public Key (verification)',
              hexString: _publicKeyHex,
            ),
            const SizedBox(height: 24),

            // Plaintext input
            TextField(
              controller: _plaintextController,
              decoration: const InputDecoration(
                labelText: 'Plaintext',
                hintText: 'Enter text to seal through the vault pipeline...',
                border: OutlineInputBorder(),
              ),
              maxLines: 3,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _aadController,
              decoration: const InputDecoration(
                labelText: 'AAD (optional, defaults to "flutter:vault")',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),

            Wrap(
              spacing: 12,
              runSpacing: 8,
              children: [
                FilledButton.icon(
                  onPressed: _seal,
                  icon: const Icon(Icons.lock, size: 18),
                  label: const Text('Seal'),
                ),
                OutlinedButton.icon(
                  onPressed: _open,
                  icon: const Icon(Icons.lock_open, size: 18),
                  label: const Text('Open'),
                ),
              ],
            ),
            const SizedBox(height: 24),

            if (_ciphertextHex.isNotEmpty) ...[
              Text('Vault Packet', style: theme.textTheme.titleMedium),
              const SizedBox(height: 12),
              HexDisplay(label: 'Ciphertext', hexString: _ciphertextHex),
              const SizedBox(height: 8),
              HexDisplay(label: 'Ed25519 Signature (64 B)', hexString: _signatureHex),
              const SizedBox(height: 8),
              HexDisplay(label: 'Argon2id Salt (16 B)', hexString: _saltHex),
              const SizedBox(height: 16),
            ],

            if (_decryptedText.isNotEmpty)
              ResultCard.success(
                _decryptedText,
                title: 'Recovered Plaintext',
              ),

            // ════════════════════════════════════════════════════════════
            // Entropy Boost (Two-Factor) section
            // ════════════════════════════════════════════════════════════
            const Divider(height: 48),
            Text(
              'Entropy Boost (Two-Factor)',
              style: theme.textTheme.titleLarge,
            ),
            const SizedBox(height: 4),
            Text(
              'When enabled, sealing requires a boost file as a second factor. '
              'Opening without the same boost file will fail.',
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 16),

            SwitchListTile(
              title: const Text('Enable entropy boost'),
              subtitle: const Text('Require a media file as second factor'),
              value: _boostEnabled,
              onChanged: (val) {
                setState(() => _boostEnabled = val);
              },
            ),

            if (_boostEnabled) ...[
              const SizedBox(height: 12),
              Row(
                children: [
                  OutlinedButton.icon(
                    onPressed: _pickBoostFile,
                    icon: const Icon(Icons.folder_open, size: 18),
                    label: const Text('Select Boost File'),
                  ),
                  const SizedBox(width: 16),
                  if (_boostFilePath != null)
                    Expanded(
                      child: Text(
                        _boostFilePath!,
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                ],
              ),
              if (_boostHandle != null) ...[
                const SizedBox(height: 12),
                ResultCard.success(
                  _boostStatus.isEmpty ? 'Boost file loaded' : _boostStatus,
                  title: 'Boost Ready',
                ),
                const SizedBox(height: 12),
                OutlinedButton.icon(
                  onPressed: _openWithoutBoost,
                  icon: const Icon(Icons.warning_amber, size: 18),
                  label: const Text('Open WITHOUT Boost (test failure)'),
                ),
              ],
              if (_boostError != null) ...[
                const SizedBox(height: 12),
                ResultCard.error(_boostError!),
              ],
            ],
          ],
          const SizedBox(height: 32),
        ],
      ),
    );
  }
}
