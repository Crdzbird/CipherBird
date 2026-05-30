import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../cryptolib_ffi.dart';
import '../widgets/hex_display.dart';
import '../widgets/result_card.dart';

class LavaRandClientPage extends StatefulWidget {
  final CryptoLib lib;

  const LavaRandClientPage({super.key, required this.lib});

  @override
  State<LavaRandClientPage> createState() => _LavaRandClientPageState();
}

class _LavaRandClientPageState extends State<LavaRandClientPage>
    with AutomaticKeepAliveClientMixin {
  final _urlController = TextEditingController(text: 'http://localhost:8443');
  final _messageController = TextEditingController();

  // Connection state
  bool _connected = false;
  Map<String, dynamic>? _serverStatus;
  String? _connectionError;

  // Client identity state
  String? _filePath;
  Uint8List? _clientPublicKey;
  Uint8List? _clientSecretKey;
  String _clientPubKeyHex = '';

  // Enroll state
  String? _enrollResult;
  String? _enrollError;

  // Challenge-Response state
  String _challengeHex = '';
  String _signatureHex = '';
  String? _verifyResult;
  String? _challengeError;

  // Encrypt state
  String _ciphertextHex = '';
  String _lastKeyId = '';
  String? _encryptError;

  // Decrypt state
  String _decryptedText = '';
  String? _decryptError;

  // Key rotation state
  String? _rotateResult;
  String? _rotateError;

  // Full demo state
  List<String> _demoLog = [];
  bool _demoRunning = false;

  @override
  bool get wantKeepAlive => true;

  @override
  void dispose() {
    _urlController.dispose();
    _messageController.dispose();
    super.dispose();
  }

  String get _baseUrl => _urlController.text.trimRight();

  // ---------------------------------------------------------------------------
  // HTTP helpers
  // ---------------------------------------------------------------------------

  Future<Map<String, dynamic>> _get(String path) async {
    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 5);
    try {
      final uri = Uri.parse('$_baseUrl$path');
      final request = await client.getUrl(uri);
      final response = await request.close();
      final body = await response.transform(utf8.decoder).join();
      if (response.statusCode >= 400) {
        throw HttpException('HTTP ${response.statusCode}: $body');
      }
      return jsonDecode(body) as Map<String, dynamic>;
    } finally {
      client.close();
    }
  }

  Future<Map<String, dynamic>> _post(
      String path, Map<String, dynamic> payload) async {
    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 5);
    try {
      final uri = Uri.parse('$_baseUrl$path');
      final request = await client.postUrl(uri);
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode(payload));
      final response = await request.close();
      final body = await response.transform(utf8.decoder).join();
      if (response.statusCode >= 400) {
        throw HttpException('HTTP ${response.statusCode}: $body');
      }
      return jsonDecode(body) as Map<String, dynamic>;
    } finally {
      client.close();
    }
  }

  // ---------------------------------------------------------------------------
  // Connection
  // ---------------------------------------------------------------------------

  Future<void> _checkStatus() async {
    try {
      final status = await _get('/status');
      setState(() {
        _serverStatus = status;
        _connected = true;
        _connectionError = null;
      });
    } catch (e) {
      setState(() {
        _connected = false;
        _serverStatus = null;
        _connectionError = e.toString();
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Client identity
  // ---------------------------------------------------------------------------

  Future<void> _pickFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select entropy source for Ed25519 identity',
    );
    if (result != null && result.files.single.path != null) {
      _deriveIdentity(result.files.single.path!);
    }
  }

  void _deriveIdentity(String path) {
    Pointer<Void>? handle;
    try {
      handle = widget.lib.entropyFromFileDeterministic(path);
      final keys = widget.lib.entropyDeriveAll(handle);
      final kp = widget.lib.ed25519KeygenFromSeed(keys.signingSeed);

      setState(() {
        _filePath = path;
        _clientPublicKey = Uint8List.fromList(kp.publicKey);
        _clientSecretKey = Uint8List.fromList(kp.secretKey);
        _clientPubKeyHex = toHex(_clientPublicKey!);
      });
    } catch (e) {
      setState(() {
        _filePath = path;
        _clientPublicKey = null;
        _clientSecretKey = null;
        _clientPubKeyHex = '';
        _connectionError = 'Identity derivation failed: $e';
      });
    } finally {
      if (handle != null) widget.lib.entropyFree(handle);
    }
  }

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  Future<void> _enroll() async {
    if (_clientPublicKey == null) {
      setState(() => _enrollError = 'Select an entropy file first.');
      return;
    }
    try {
      final resp = await _post('/enroll', {
        'pubkey': _clientPubKeyHex,
      });
      setState(() {
        _enrollResult = resp.toString();
        _enrollError = null;
      });
    } catch (e) {
      setState(() {
        _enrollResult = null;
        _enrollError = e.toString();
      });
    }
  }

  Future<void> _challengeResponse() async {
    if (_clientPublicKey == null || _clientSecretKey == null) {
      setState(() => _challengeError = 'Select an entropy file first.');
      return;
    }
    try {
      // Step 1: get challenge
      final challengeResp = await _post('/challenge', {
        'pubkey': _clientPubKeyHex,
      });
      final challengeHex = challengeResp['challenge'] as String;
      final challengeBytes = fromHex(challengeHex);

      // Step 2: sign challenge locally
      final signature = widget.lib.ed25519Sign(challengeBytes, _clientSecretKey!);
      final sigHex = toHex(signature);

      // Step 3: verify
      final verifyResp = await _post('/verify', {
        'challenge': challengeHex,
        'signature': sigHex,
        'pubkey': _clientPubKeyHex,
      });

      setState(() {
        _challengeHex = challengeHex;
        _signatureHex = sigHex;
        _verifyResult = (verifyResp['verified'] == true) ? 'verified' : 'rejected';
        _challengeError = null;
      });
    } catch (e) {
      setState(() {
        _challengeHex = '';
        _signatureHex = '';
        _verifyResult = null;
        _challengeError = e.toString();
      });
    }
  }

  Future<void> _encrypt() async {
    final msg = _messageController.text;
    if (msg.isEmpty) {
      setState(() => _encryptError = 'Enter a message to encrypt.');
      return;
    }
    try {
      final resp = await _post('/encrypt', {
        'plaintext': msg,
      });
      setState(() {
        _ciphertextHex = resp['ciphertext'] as String? ?? '';
        _lastKeyId = resp['key_id']?.toString() ?? '';
        _encryptError = null;
      });
    } catch (e) {
      setState(() {
        _ciphertextHex = '';
        _lastKeyId = '';
        _encryptError = e.toString();
      });
    }
  }

  Future<void> _decrypt() async {
    if (_ciphertextHex.isEmpty || _lastKeyId.isEmpty) {
      setState(() => _decryptError = 'Encrypt something first.');
      return;
    }
    try {
      final resp = await _post('/decrypt', {
        'ciphertext': _ciphertextHex,
        'key_id': _lastKeyId,
      });
      setState(() {
        _decryptedText = resp['plaintext'] as String? ?? '';
        _decryptError = null;
      });
    } catch (e) {
      setState(() {
        _decryptedText = '';
        _decryptError = e.toString();
      });
    }
  }

  Future<void> _rotateKey() async {
    try {
      final resp = await _get('/rotate');
      setState(() {
        _rotateResult = resp.toString();
        _rotateError = null;
      });
    } catch (e) {
      setState(() {
        _rotateResult = null;
        _rotateError = e.toString();
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Full demo
  // ---------------------------------------------------------------------------

  Future<void> _runFullDemo() async {
    if (_clientPublicKey == null || _clientSecretKey == null) {
      setState(() {
        _demoLog = ['Select an entropy file before running the demo.'];
      });
      return;
    }

    setState(() {
      _demoRunning = true;
      _demoLog = ['Starting full demo...'];
    });

    void log(String msg) {
      setState(() => _demoLog = [..._demoLog, msg]);
    }

    try {
      // 1. Enroll
      log('1. Enrolling client public key...');
      final enrollResp = await _post('/enroll', {'pubkey': _clientPubKeyHex});
      log('   \u2713 Enrolled. Server response: ${enrollResp.toString()}');

      // 2. Challenge-Response
      log('2. Requesting challenge...');
      final chalResp = await _post('/challenge', {'pubkey': _clientPubKeyHex});
      final chalHex = chalResp['challenge'] as String;
      log('   \u2713 Challenge received: ${chalHex.substring(0, 16)}...');

      final sig = widget.lib.ed25519Sign(fromHex(chalHex), _clientSecretKey!);
      final sigHex = toHex(sig);
      log('   Signing challenge locally...');

      final verResp = await _post('/verify', {
        'challenge': chalHex,
        'signature': sigHex,
        'pubkey': _clientPubKeyHex,
      });
      final verified = verResp['verified'] == true;
      log('   \u2713 Verification: ${verified ? "PASSED" : "FAILED"}');

      // 3. Encrypt
      const demoMsg = 'Hello from Flutter LavaRand client!';
      log('3. Encrypting: "$demoMsg"');
      final encResp = await _post('/encrypt', {'plaintext': demoMsg});
      final ct = encResp['ciphertext'] as String? ?? '';
      final kid = encResp['key_id']?.toString() ?? '';
      log('   \u2713 Encrypted. Key ID: $kid, ciphertext: ${ct.substring(0, 16.clamp(0, ct.length))}...');

      // 4. Decrypt
      log('4. Decrypting...');
      final decResp = await _post('/decrypt', {
        'ciphertext': ct,
        'key_id': kid,
      });
      final pt = decResp['plaintext'] as String? ?? '';
      log('   \u2713 Decrypted: "$pt"');

      // 5. Status
      log('5. Checking server status...');
      final status = await _get('/status');
      log('   \u2713 Status: ${status.toString()}');

      log('');
      log('\u2713 Full demo completed successfully.');
    } catch (e) {
      log('   ERROR: $e');
    } finally {
      setState(() => _demoRunning = false);
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

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
            'LavaRand Server Client',
            style: theme.textTheme.headlineSmall,
          ),
          const SizedBox(height: 8),
          Text(
            'Connect to a running LavaRand server to enroll, authenticate, '
            'encrypt/decrypt, and rotate keys using entropy-derived cryptography.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 24),

          // ── Connection ─────────────────────────────────────────────────
          _sectionCard(
            theme,
            title: 'Connection',
            icon: Icons.cloud,
            children: [
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _urlController,
                      decoration: const InputDecoration(
                        labelText: 'Server URL',
                        hintText: 'http://localhost:8443',
                        border: OutlineInputBorder(),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  FilledButton.icon(
                    onPressed: _checkStatus,
                    icon: const Icon(Icons.sync, size: 18),
                    label: const Text('Check Status'),
                  ),
                  const SizedBox(width: 12),
                  _connectionDot(),
                ],
              ),
              if (_connectionError != null) ...[
                const SizedBox(height: 12),
                ResultCard.error(_connectionError!),
              ],
              if (_serverStatus != null) ...[
                const SizedBox(height: 12),
                ..._serverStatus!.entries.map(
                  (e) => _infoRow(e.key, e.value.toString()),
                ),
              ],
            ],
          ),
          const SizedBox(height: 16),

          // ── Client Identity ────────────────────────────────────────────
          _sectionCard(
            theme,
            title: 'Client Identity',
            icon: Icons.fingerprint,
            children: [
              Row(
                children: [
                  FilledButton.icon(
                    onPressed: _pickFile,
                    icon: const Icon(Icons.folder_open, size: 18),
                    label: const Text('Select Entropy File'),
                  ),
                  const SizedBox(width: 16),
                  if (_filePath != null)
                    Expanded(
                      child: Text(
                        _filePath!,
                        style: const TextStyle(
                            fontFamily: 'monospace', fontSize: 12),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                ],
              ),
              if (_clientPubKeyHex.isNotEmpty) ...[
                const SizedBox(height: 12),
                HexDisplay(
                  label: 'Derived Ed25519 Public Key',
                  hexString: _clientPubKeyHex,
                ),
              ],
            ],
          ),
          const SizedBox(height: 16),

          // ── 1. Enroll ──────────────────────────────────────────────────
          _sectionCard(
            theme,
            title: '1. Enroll',
            icon: Icons.person_add,
            children: [
              Text(
                'Register your public key with the server.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                onPressed: _clientPublicKey != null ? _enroll : null,
                icon: const Icon(Icons.send, size: 18),
                label: const Text('Enroll'),
              ),
              if (_enrollError != null) ...[
                const SizedBox(height: 12),
                ResultCard.error(_enrollError!),
              ],
              if (_enrollResult != null) ...[
                const SizedBox(height: 12),
                ResultCard.success(_enrollResult!, title: 'Server Response'),
              ],
            ],
          ),
          const SizedBox(height: 16),

          // ── 2. Challenge-Response ──────────────────────────────────────
          _sectionCard(
            theme,
            title: '2. Challenge-Response',
            icon: Icons.security,
            children: [
              Text(
                'Request a challenge, sign it locally with your Ed25519 key, '
                'then send the signature for verification.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                onPressed:
                    _clientPublicKey != null ? _challengeResponse : null,
                icon: const Icon(Icons.verified_user, size: 18),
                label: const Text('Run Challenge-Response'),
              ),
              if (_challengeError != null) ...[
                const SizedBox(height: 12),
                ResultCard.error(_challengeError!),
              ],
              if (_challengeHex.isNotEmpty) ...[
                const SizedBox(height: 12),
                HexDisplay(label: 'Challenge', hexString: _challengeHex),
                const SizedBox(height: 8),
                HexDisplay(label: 'Signature', hexString: _signatureHex),
                const SizedBox(height: 8),
                if (_verifyResult == 'verified')
                  ResultCard.success('Signature VERIFIED by server.'),
                if (_verifyResult == 'rejected')
                  ResultCard.error('Signature REJECTED by server.'),
              ],
            ],
          ),
          const SizedBox(height: 16),

          // ── 3. Encrypt ─────────────────────────────────────────────────
          _sectionCard(
            theme,
            title: '3. Encrypt',
            icon: Icons.lock,
            children: [
              Text(
                'Server uses a fresh LavaRand key for this encryption.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _messageController,
                decoration: const InputDecoration(
                  labelText: 'Plaintext message',
                  hintText: 'Enter text to encrypt...',
                  border: OutlineInputBorder(),
                ),
                maxLines: 2,
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                onPressed: _encrypt,
                icon: const Icon(Icons.lock, size: 18),
                label: const Text('Encrypt'),
              ),
              if (_encryptError != null) ...[
                const SizedBox(height: 12),
                ResultCard.error(_encryptError!),
              ],
              if (_ciphertextHex.isNotEmpty) ...[
                const SizedBox(height: 12),
                HexDisplay(label: 'Ciphertext', hexString: _ciphertextHex),
                const SizedBox(height: 8),
                _infoRow('Key ID', _lastKeyId),
                const SizedBox(height: 4),
                Text(
                  'Server used a fresh LavaRand key for this encryption.',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.primary,
                    fontStyle: FontStyle.italic,
                  ),
                ),
              ],
            ],
          ),
          const SizedBox(height: 16),

          // ── 4. Decrypt ─────────────────────────────────────────────────
          _sectionCard(
            theme,
            title: '4. Decrypt',
            icon: Icons.lock_open,
            children: [
              if (_ciphertextHex.isNotEmpty) ...[
                _infoRow('Ciphertext',
                    '${_ciphertextHex.substring(0, 32.clamp(0, _ciphertextHex.length))}...'),
                _infoRow('Key ID', _lastKeyId),
                const SizedBox(height: 12),
              ],
              if (_ciphertextHex.isEmpty)
                Text(
                  'Encrypt something first.',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              FilledButton.icon(
                onPressed:
                    _ciphertextHex.isNotEmpty ? _decrypt : null,
                icon: const Icon(Icons.lock_open, size: 18),
                label: const Text('Decrypt'),
              ),
              if (_decryptError != null) ...[
                const SizedBox(height: 12),
                ResultCard.error(_decryptError!),
              ],
              if (_decryptedText.isNotEmpty) ...[
                const SizedBox(height: 12),
                ResultCard.success(
                  _decryptedText,
                  title: 'Recovered Plaintext',
                ),
              ],
            ],
          ),
          const SizedBox(height: 16),

          // ── 5. Key Rotation ────────────────────────────────────────────
          _sectionCard(
            theme,
            title: '5. Key Rotation',
            icon: Icons.autorenew,
            children: [
              Text(
                'Trigger key rotation on the server.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                onPressed: _rotateKey,
                icon: const Icon(Icons.autorenew, size: 18),
                label: const Text('Rotate Keys'),
              ),
              if (_rotateError != null) ...[
                const SizedBox(height: 12),
                ResultCard.error(_rotateError!),
              ],
              if (_rotateResult != null) ...[
                const SizedBox(height: 12),
                ResultCard.success(_rotateResult!, title: 'Rotation Result'),
              ],
            ],
          ),
          const SizedBox(height: 16),

          // ── 6. Full Demo ───────────────────────────────────────────────
          _sectionCard(
            theme,
            title: '6. Full Demo',
            icon: Icons.play_circle,
            children: [
              Text(
                'Runs all steps automatically: enroll, challenge-response, '
                'encrypt, decrypt, and status check.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                onPressed: (_clientPublicKey != null && !_demoRunning)
                    ? _runFullDemo
                    : null,
                icon: _demoRunning
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.play_arrow, size: 18),
                label: Text(_demoRunning ? 'Running...' : 'Run Full Demo'),
              ),
              if (_demoLog.isNotEmpty) ...[
                const SizedBox(height: 12),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(8),
                    border:
                        Border.all(color: theme.colorScheme.outlineVariant),
                  ),
                  child: SelectableText(
                    _demoLog.join('\n'),
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      height: 1.5,
                    ),
                  ),
                ),
              ],
            ],
          ),
          const SizedBox(height: 32),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  Widget _connectionDot() {
    return Container(
      width: 14,
      height: 14,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: _connected ? Colors.green : Colors.grey,
        boxShadow: _connected
            ? [
                BoxShadow(
                  color: Colors.green.withValues(alpha: 0.4),
                  blurRadius: 6,
                  spreadRadius: 1,
                ),
              ]
            : null,
      ),
    );
  }

  Widget _sectionCard(
    ThemeData theme, {
    required String title,
    required IconData icon,
    required List<Widget> children,
  }) {
    return Card(
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
            Row(
              children: [
                Icon(icon, size: 20, color: theme.colorScheme.primary),
                const SizedBox(width: 8),
                Text(title, style: theme.textTheme.titleMedium),
              ],
            ),
            const SizedBox(height: 12),
            ...children,
          ],
        ),
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
