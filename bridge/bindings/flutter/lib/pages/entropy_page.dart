import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import '../cryptolib_ffi.dart';
import '../widgets/hex_display.dart';
import '../widgets/result_card.dart';

enum EntropyMode { lavarand, deterministic }

class EntropyPage extends StatefulWidget {
  final CryptoLib lib;

  const EntropyPage({super.key, required this.lib});

  @override
  State<EntropyPage> createState() => _EntropyPageState();
}

class _EntropyPageState extends State<EntropyPage>
    with AutomaticKeepAliveClientMixin {
  final _plaintextController = TextEditingController();
  final _aadController = TextEditingController();

  EntropyMode _mode = EntropyMode.lavarand;
  String? _filePath;
  Pointer<Void>? _entropyHandle;
  EntropyInfoResult? _info;
  DerivedKeysResult? _derivedKeys;
  String? _error;

  // Seal from file state
  Packet? _sealedPacket;
  String _sealedCiphertextHex = '';
  String _openedText = '';
  String? _sealError;

  // Key from file state
  String _keyFromFileHex = '';

  // Credential validation state
  Uint8List? _storedFingerprint;
  Uint8List? _storedSignSecret;
  String? _credentialResult;
  String _challengeHex = '';
  String _responseHex = '';

  @override
  bool get wantKeepAlive => true;

  @override
  void dispose() {
    _freeHandle();
    _plaintextController.dispose();
    _aadController.dispose();
    super.dispose();
  }

  void _freeHandle() {
    if (_entropyHandle != null) {
      widget.lib.entropyFree(_entropyHandle!);
      _entropyHandle = null;
    }
  }

  Future<void> _pickFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select a media file for entropy',
    );
    if (result != null && result.files.single.path != null) {
      setState(() {
        _filePath = result.files.single.path;
        _derivedKeys = null;
        _info = null;
        _error = null;
        _sealedPacket = null;
        _sealedCiphertextHex = '';
        _openedText = '';
        _sealError = null;
        _keyFromFileHex = '';
      });
    }
  }

  void _harvestEntropy() {
    if (_filePath == null) {
      setState(() => _error = 'Select a file first.');
      return;
    }

    _freeHandle();

    try {
      Pointer<Void> handle;
      switch (_mode) {
        case EntropyMode.lavarand:
          handle = widget.lib.entropyFromFile(_filePath!);
          break;
        case EntropyMode.deterministic:
          handle = widget.lib.entropyFromFileDeterministic(_filePath!);
          break;
      }

      _entropyHandle = handle;
      final info = widget.lib.entropyInfo(handle);
      final keys = widget.lib.entropyDeriveAll(handle);

      setState(() {
        _info = info;
        _derivedKeys = keys;
        _error = null;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _derivedKeys = null;
        _info = null;
      });
    }
  }

  void _refreshEntropy() {
    if (_entropyHandle == null) {
      setState(() => _error = 'Harvest entropy first.');
      return;
    }

    try {
      widget.lib.entropyRefresh(_entropyHandle!);
      final keys = widget.lib.entropyDeriveAll(_entropyHandle!);
      setState(() {
        _derivedKeys = keys;
        _error = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  void _sealFromFile() {
    if (_filePath == null) {
      setState(() => _sealError = 'Select a file first.');
      return;
    }
    final ptText = _plaintextController.text;
    if (ptText.isEmpty) {
      setState(() => _sealError = 'Enter plaintext to encrypt.');
      return;
    }

    try {
      final aad = _aadController.text.isEmpty ? 'flutter-gui' : _aadController.text;
      final pkt = widget.lib.sealFromFile(_filePath!, ptText, aad);
      setState(() {
        _sealedPacket = pkt;
        _sealedCiphertextHex = toHex(pkt.ciphertext);
        _openedText = '';
        _sealError = null;
      });
    } catch (e) {
      setState(() => _sealError = e.toString());
    }
  }

  void _openFromFile() {
    if (_filePath == null || _sealedPacket == null) {
      setState(() => _sealError = 'Seal something first.');
      return;
    }

    try {
      final aad = _aadController.text.isEmpty ? 'flutter-gui' : _aadController.text;
      final pt = widget.lib.openFromFile(_filePath!, _sealedPacket!, aad);
      setState(() {
        _openedText = utf8.decode(pt);
        _sealError = null;
      });
    } catch (e) {
      setState(() => _sealError = e.toString());
    }
  }

  void _keyFromFile() {
    if (_filePath == null) {
      setState(() => _error = 'Select a file first.');
      return;
    }

    try {
      final key = widget.lib.keyFromFile(_filePath!);
      setState(() {
        _keyFromFileHex = toHex(key);
        _error = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  void _enrollCredential() {
    if (_filePath == null) {
      setState(() => _credentialResult = null);
      return;
    }

    Pointer<Void>? handle;
    try {
      handle = widget.lib.entropyFromFileDeterministic(_filePath!);
      final keys = widget.lib.entropyDeriveAll(handle);
      final kp = widget.lib.ed25519KeygenFromSeed(keys.signingSeed);

      setState(() {
        _storedFingerprint = Uint8List.fromList(kp.publicKey);
        _storedSignSecret = Uint8List.fromList(kp.secretKey);
        _credentialResult = 'enrolled';
        _challengeHex = '';
        _responseHex = '';
      });
    } catch (e) {
      setState(() => _credentialResult = 'error:${e.toString()}');
    } finally {
      if (handle != null) widget.lib.entropyFree(handle);
    }
  }

  void _verifyCredential() {
    if (_filePath == null || _storedFingerprint == null) {
      setState(() => _credentialResult = 'error:Enroll first, then verify.');
      return;
    }

    Pointer<Void>? handle;
    try {
      handle = widget.lib.entropyFromFileDeterministic(_filePath!);
      final keys = widget.lib.entropyDeriveAll(handle);
      final kp = widget.lib.ed25519KeygenFromSeed(keys.signingSeed);

      final match = widget.lib.secureEqual(kp.publicKey, _storedFingerprint!);

      setState(() {
        _credentialResult = match ? 'granted' : 'denied';
        _challengeHex = '';
        _responseHex = '';
      });
    } catch (e) {
      setState(() => _credentialResult = 'error:${e.toString()}');
    } finally {
      if (handle != null) widget.lib.entropyFree(handle);
    }
  }

  void _challengeResponse() {
    if (_filePath == null || _storedFingerprint == null) {
      setState(() => _credentialResult = 'error:Enroll first.');
      return;
    }

    Pointer<Void>? handle;
    try {
      handle = widget.lib.entropyFromFileDeterministic(_filePath!);
      final keys = widget.lib.entropyDeriveAll(handle);
      final kp = widget.lib.ed25519KeygenFromSeed(keys.signingSeed);

      final challenge = widget.lib.randomBytes(32);
      final signature = widget.lib.ed25519Sign(challenge, kp.secretKey);
      final valid = widget.lib.ed25519Verify(
        challenge,
        signature,
        _storedFingerprint!,
      );

      // Prove that an attacker keypair is rejected
      final attackerSeed = widget.lib.randomBytes(32);
      final attackerKp = widget.lib.ed25519KeygenFromSeed(attackerSeed);
      final attackerSig = widget.lib.ed25519Sign(challenge, attackerKp.secretKey);
      final attackerValid = widget.lib.ed25519Verify(
        challenge,
        attackerSig,
        _storedFingerprint!,
      );

      setState(() {
        _challengeHex = toHex(challenge);
        _responseHex = toHex(signature);
        _credentialResult = valid && !attackerValid
            ? 'challenge_ok'
            : 'challenge_fail';
      });
    } catch (e) {
      setState(() => _credentialResult = 'error:${e.toString()}');
    } finally {
      if (handle != null) widget.lib.entropyFree(handle);
    }
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
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
            'Media Entropy -- Your Files Are Your Keys',
            style: theme.textTheme.headlineSmall,
          ),
          const SizedBox(height: 8),
          Text(
            'LavaRand-inspired entropy harvesting from any media file. '
            'Photos, audio, and video contain physical entropy that no algorithm can predict.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 24),

          // Mode selector
          SegmentedButton<EntropyMode>(
            segments: const [
              ButtonSegment(
                value: EntropyMode.lavarand,
                label: Text('LavaRand'),
                icon: Icon(Icons.shuffle),
              ),
              ButtonSegment(
                value: EntropyMode.deterministic,
                label: Text('Deterministic'),
                icon: Icon(Icons.lock_clock),
              ),
            ],
            selected: {_mode},
            onSelectionChanged: (selected) {
              setState(() => _mode = selected.first);
            },
          ),
          const SizedBox(height: 8),
          Text(
            _mode == EntropyMode.lavarand
                ? 'LavaRand: mixes system entropy, different keys every call. Best for session keys.'
                : 'Deterministic: same file always produces same keys. Best for key agreement.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 24),

          // File picker
          Row(
            children: [
              FilledButton.icon(
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

          // Action buttons
          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: _harvestEntropy,
                icon: const Icon(Icons.bolt, size: 18),
                label: const Text('Harvest Entropy'),
              ),
              OutlinedButton.icon(
                onPressed: _refreshEntropy,
                icon: const Icon(Icons.refresh, size: 18),
                label: const Text('Refresh Entropy'),
              ),
              OutlinedButton.icon(
                onPressed: _keyFromFile,
                icon: const Icon(Icons.key, size: 18),
                label: const Text('Key from File'),
              ),
            ],
          ),
          const SizedBox(height: 24),

          if (_error != null) ResultCard.error(_error!),

          // Entropy info
          if (_info != null) ...[
            Card(
              elevation: 0,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
                side: BorderSide(color: theme.colorScheme.outlineVariant),
              ),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Entropy Source Info',
                        style: theme.textTheme.titleMedium),
                    const SizedBox(height: 12),
                    _infoRow('File', _info!.path),
                    _infoRow('Size', _formatBytes(_info!.fileSize)),
                    _infoRow('Chunks Read', '${_info!.chunksRead}'),
                    _infoRow('Entropy Estimate',
                        '${_info!.entropyBits.toStringAsFixed(1)} bits'),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
          ],

          // Derived keys
          if (_derivedKeys != null) ...[
            Text('Derived Keys (6)', style: theme.textTheme.titleMedium),
            const SizedBox(height: 12),
            HexDisplay(
              label: 'Symmetric Key (32 B)',
              hexString: toHex(_derivedKeys!.symmetricKey),
            ),
            const SizedBox(height: 12),
            HexDisplay(
              label: 'Vault Master Key (32 B)',
              hexString: toHex(_derivedKeys!.vaultMasterKey),
            ),
            const SizedBox(height: 12),
            HexDisplay(
              label: 'Signing Seed (32 B)',
              hexString: toHex(_derivedKeys!.signingSeed),
            ),
            const SizedBox(height: 12),
            HexDisplay(
              label: 'Box Seed (32 B)',
              hexString: toHex(_derivedKeys!.boxSeed),
            ),
            const SizedBox(height: 12),
            HexDisplay(
              label: 'Stream Key (32 B)',
              hexString: toHex(_derivedKeys!.streamKey),
            ),
            const SizedBox(height: 12),
            HexDisplay(
              label: 'Raw Entropy (64 B)',
              hexString: toHex(_derivedKeys!.rawEntropy),
            ),
            const SizedBox(height: 24),
          ],

          // Key from file
          if (_keyFromFileHex.isNotEmpty) ...[
            HexDisplay(label: 'Key from File (one-liner)', hexString: _keyFromFileHex),
            const SizedBox(height: 24),
          ],

          // Encrypt with this file section
          const Divider(),
          const SizedBox(height: 16),
          Text('Encrypt with this File', style: theme.textTheme.titleMedium),
          const SizedBox(height: 8),
          Text(
            'Uses deterministic mode internally so the same file can decrypt.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _plaintextController,
            decoration: const InputDecoration(
              labelText: 'Plaintext',
              hintText: 'Enter text to encrypt with this file...',
              border: OutlineInputBorder(),
            ),
            maxLines: 2,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _aadController,
            decoration: const InputDecoration(
              labelText: 'AAD (optional, defaults to "flutter-gui")',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: _sealFromFile,
                icon: const Icon(Icons.lock, size: 18),
                label: const Text('seal_from_file'),
              ),
              OutlinedButton.icon(
                onPressed: _openFromFile,
                icon: const Icon(Icons.lock_open, size: 18),
                label: const Text('open_from_file'),
              ),
            ],
          ),
          const SizedBox(height: 16),
          if (_sealError != null) ResultCard.error(_sealError!),
          if (_sealedCiphertextHex.isNotEmpty) ...[
            HexDisplay(label: 'Sealed Ciphertext', hexString: _sealedCiphertextHex),
            const SizedBox(height: 8),
            HexDisplay(label: 'Signature', hexString: toHex(_sealedPacket!.signature)),
            const SizedBox(height: 8),
            HexDisplay(label: 'KDF Salt', hexString: toHex(_sealedPacket!.kdfSalt)),
            const SizedBox(height: 16),
          ],
          if (_openedText.isNotEmpty)
            ResultCard.success(
              _openedText,
              title: 'Recovered Plaintext',
            ),
          const SizedBox(height: 24),

          // File as Credential — Authentication
          const Divider(),
          const SizedBox(height: 16),
          Text('File as Credential \u2014 Authentication',
              style: theme.textTheme.titleMedium),
          const SizedBox(height: 8),
          Text(
            'Use a media file as a biometric-like credential. '
            'Deterministic entropy derives an Ed25519 identity from the file content.',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 16),

          // Enrollment & Verification buttons
          Text('1. Enrollment', style: theme.textTheme.labelLarge),
          const SizedBox(height: 8),
          FilledButton.icon(
            onPressed: _filePath != null ? _enrollCredential : null,
            icon: const Icon(Icons.fingerprint, size: 18),
            label: const Text('Enroll with this File'),
          ),
          const SizedBox(height: 16),

          if (_credentialResult == 'enrolled' && _storedFingerprint != null) ...[
            ResultCard.success('Credential enrolled successfully.'),
            const SizedBox(height: 8),
            HexDisplay(
              label: 'Stored Fingerprint (Ed25519 Public Key)',
              hexString: toHex(_storedFingerprint!),
            ),
            const SizedBox(height: 16),
          ],

          Text('2. Verification', style: theme.textTheme.labelLarge),
          const SizedBox(height: 8),
          FilledButton.icon(
            onPressed: _storedFingerprint != null ? _verifyCredential : null,
            icon: const Icon(Icons.verified_user, size: 18),
            label: const Text('Verify with this File'),
          ),
          const SizedBox(height: 8),

          if (_credentialResult == 'granted')
            ResultCard.success('ACCESS GRANTED'),
          if (_credentialResult == 'denied')
            ResultCard.error('ACCESS DENIED'),
          const SizedBox(height: 16),

          Text('3. Challenge-Response Proof', style: theme.textTheme.labelLarge),
          const SizedBox(height: 8),
          FilledButton.icon(
            onPressed: _storedFingerprint != null ? _challengeResponse : null,
            icon: const Icon(Icons.security, size: 18),
            label: const Text('Challenge-Response Proof'),
          ),
          const SizedBox(height: 8),

          if (_challengeHex.isNotEmpty) ...[
            HexDisplay(label: 'Challenge (32 B)', hexString: _challengeHex),
            const SizedBox(height: 8),
            HexDisplay(label: 'Response (Signature)', hexString: _responseHex),
            const SizedBox(height: 8),
            if (_credentialResult == 'challenge_ok') ...[
              ResultCard.success(
                'Signature verified against stored fingerprint.\n'
                'Attacker keypair signature correctly rejected.',
              ),
            ],
            if (_credentialResult == 'challenge_fail')
              ResultCard.error('Challenge-response verification failed.'),
            const SizedBox(height: 16),
          ],

          if (_credentialResult != null &&
              _credentialResult!.startsWith('error:'))
            ResultCard.error(_credentialResult!.substring(6)),

          const SizedBox(height: 32),
        ],
      ),
    );
  }

  Widget _infoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          SizedBox(
            width: 140,
            child: Text(label,
                style: const TextStyle(fontWeight: FontWeight.w500)),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }
}
