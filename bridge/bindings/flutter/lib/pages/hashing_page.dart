import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../cryptolib_ffi.dart';
import '../widgets/hex_display.dart';
import '../widgets/result_card.dart';

class HashingPage extends StatefulWidget {
  final CryptoLib lib;

  const HashingPage({super.key, required this.lib});

  @override
  State<HashingPage> createState() => _HashingPageState();
}

class _HashingPageState extends State<HashingPage>
    with AutomaticKeepAliveClientMixin {
  final _msgController = TextEditingController();
  final _keyController = TextEditingController();
  String _resultHex = '';
  String _resultLabel = '';
  String? _error;

  // ── HMAC verify state ──
  Uint8List? _lastHmac;
  Uint8List? _lastHmacKey;
  String? _hmacVerifyResult;
  bool? _hmacVerifyOk;

  // ── Argon2id state ──
  final _passwordController = TextEditingController();
  String _argon2idHashResult = '';
  String? _argon2idVerifyResult;
  bool? _argon2idVerifyOk;
  String? _argon2idError;

  @override
  bool get wantKeepAlive => true;

  @override
  void dispose() {
    _msgController.dispose();
    _keyController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  void _hash(String algorithm) {
    final msgText = _msgController.text;
    if (msgText.isEmpty) {
      setState(() {
        _error = 'Please enter a message to hash.';
        _resultHex = '';
      });
      return;
    }

    try {
      final msg = Uint8List.fromList(msgText.codeUnits);
      final keyText = _keyController.text;
      Uint8List? key;
      if (keyText.isNotEmpty) {
        key = Uint8List.fromList(keyText.codeUnits);
      }

      Uint8List hash;
      switch (algorithm) {
        case 'BLAKE2b':
          hash = widget.lib.blake2b(msg, key);
          break;
        case 'SHA-256':
          hash = widget.lib.sha256(msg);
          break;
        case 'SHA-512':
          hash = widget.lib.sha512(msg);
          break;
        case 'HMAC-SHA512':
          if (key == null || key.isEmpty) {
            setState(() {
              _error = 'HMAC-SHA512 requires a key. Enter one in the key field.';
              _resultHex = '';
            });
            return;
          }
          hash = widget.lib.hmacSha512(msg, key);
          // Store for verify operations
          _lastHmac = hash;
          _lastHmacKey = key;
          _hmacVerifyResult = null;
          _hmacVerifyOk = null;
          break;
        default:
          throw Exception('Unknown algorithm: $algorithm');
      }

      setState(() {
        _resultHex = toHex(hash);
        _resultLabel = '$algorithm (${hash.length} bytes)';
        _error = null;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _resultHex = '';
      });
    }
  }

  void _hmacVerify() {
    if (_lastHmac == null || _lastHmacKey == null) {
      setState(() => _error = 'Compute an HMAC-SHA512 first.');
      return;
    }
    try {
      final msg = Uint8List.fromList(_msgController.text.codeUnits);
      final ok = widget.lib.hmacSha512Verify(msg, _lastHmac!, _lastHmacKey!);
      setState(() {
        _hmacVerifyResult = ok ? 'HMAC VALID' : 'HMAC REJECTED';
        _hmacVerifyOk = ok;
        _error = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  void _hmacTamperAndVerify() {
    if (_lastHmac == null || _lastHmacKey == null) {
      setState(() => _error = 'Compute an HMAC-SHA512 first.');
      return;
    }
    try {
      final msg = Uint8List.fromList(_msgController.text.codeUnits);
      final tampered = Uint8List.fromList(_lastHmac!);
      tampered[0] ^= 0x01;
      final ok = widget.lib.hmacSha512Verify(msg, tampered, _lastHmacKey!);
      setState(() {
        _hmacVerifyResult = ok
            ? 'Tampered HMAC accepted (unexpected!)'
            : 'Tampered HMAC REJECTED (expected)';
        _hmacVerifyOk = ok;
        _error = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  // ── Argon2id actions ──

  void _argon2idHash() {
    final password = _passwordController.text;
    if (password.isEmpty) {
      setState(() => _argon2idError = 'Enter a password to hash.');
      return;
    }
    try {
      final hashBytes = widget.lib.argon2idHashStr(password);
      final phcStr = String.fromCharCodes(hashBytes).replaceAll('\x00', '');
      setState(() {
        _argon2idHashResult = phcStr;
        _argon2idVerifyResult = null;
        _argon2idVerifyOk = null;
        _argon2idError = null;
      });
    } catch (e) {
      setState(() => _argon2idError = e.toString());
    }
  }

  void _argon2idVerify() {
    if (_argon2idHashResult.isEmpty) {
      setState(() => _argon2idError = 'Hash a password first.');
      return;
    }
    try {
      final password = _passwordController.text;
      final ok = widget.lib.argon2idVerifyStr(password, _argon2idHashResult);
      setState(() {
        _argon2idVerifyResult = ok ? 'Password MATCHES' : 'Password REJECTED';
        _argon2idVerifyOk = ok;
        _argon2idError = null;
      });
    } catch (e) {
      setState(() => _argon2idError = e.toString());
    }
  }

  void _argon2idWrongPassword() {
    if (_argon2idHashResult.isEmpty) {
      setState(() => _argon2idError = 'Hash a password first.');
      return;
    }
    try {
      final ok = widget.lib.argon2idVerifyStr('wrong-password-attempt', _argon2idHashResult);
      setState(() {
        _argon2idVerifyResult = ok
            ? 'Wrong password accepted (unexpected!)'
            : 'Wrong password REJECTED (expected)';
        _argon2idVerifyOk = ok;
        _argon2idError = null;
      });
    } catch (e) {
      setState(() => _argon2idError = e.toString());
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
            'Cryptographic Hashing',
            style: Theme.of(context).textTheme.headlineSmall,
          ),
          const SizedBox(height: 8),
          Text(
            'Compute cryptographic hashes of text messages. '
            'BLAKE2b supports optional keyed hashing. '
            'HMAC-SHA512 requires a key.',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
          ),
          const SizedBox(height: 24),
          TextField(
            controller: _msgController,
            decoration: const InputDecoration(
              labelText: 'Message',
              hintText: 'Enter text to hash...',
              border: OutlineInputBorder(),
            ),
            maxLines: 3,
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _keyController,
            decoration: const InputDecoration(
              labelText: 'Key (optional, required for HMAC)',
              hintText: 'Enter key for keyed hashing...',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 20),
          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: () => _hash('BLAKE2b'),
                icon: const Icon(Icons.tag, size: 18),
                label: const Text('BLAKE2b-512'),
              ),
              FilledButton.tonalIcon(
                onPressed: () => _hash('SHA-256'),
                icon: const Icon(Icons.tag, size: 18),
                label: const Text('SHA-256'),
              ),
              FilledButton.tonalIcon(
                onPressed: () => _hash('SHA-512'),
                icon: const Icon(Icons.tag, size: 18),
                label: const Text('SHA-512'),
              ),
              OutlinedButton.icon(
                onPressed: () => _hash('HMAC-SHA512'),
                icon: const Icon(Icons.key, size: 18),
                label: const Text('HMAC-SHA512'),
              ),
            ],
          ),
          const SizedBox(height: 24),
          if (_error != null) ResultCard.error(_error!),
          if (_resultHex.isNotEmpty) ...[
            HexDisplay(label: _resultLabel, hexString: _resultHex),
          ],

          // ── HMAC Verify section ──
          if (_lastHmac != null) ...[
            const SizedBox(height: 16),
            Wrap(
              spacing: 12,
              runSpacing: 8,
              children: [
                FilledButton.tonalIcon(
                  onPressed: _hmacVerify,
                  icon: const Icon(Icons.verified, size: 18),
                  label: const Text('Verify HMAC'),
                ),
                OutlinedButton.icon(
                  onPressed: _hmacTamperAndVerify,
                  icon: const Icon(Icons.bug_report, size: 18),
                  label: const Text('Tamper & Verify'),
                ),
              ],
            ),
            if (_hmacVerifyResult != null) ...[
              const SizedBox(height: 12),
              _hmacVerifyOk == true
                  ? ResultCard.success(_hmacVerifyResult!)
                  : ResultCard.error(_hmacVerifyResult!),
            ],
          ],

          // ════════════════════════════════════════════════════════════════
          // Argon2id Password Hashing
          // ════════════════════════════════════════════════════════════════
          const Divider(height: 48),
          Text(
            'Argon2id Password Hashing',
            style: theme.textTheme.titleLarge,
          ),
          const SizedBox(height: 4),
          Text(
            'Hash passwords using Argon2id (memory-hard KDF). '
            'Produces a PHC-format string. Verify the correct password '
            'or test with a wrong password to see rejection.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 16),

          TextField(
            controller: _passwordController,
            decoration: const InputDecoration(
              labelText: 'Password',
              hintText: 'Enter a password to hash...',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 16),

          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: _argon2idHash,
                icon: const Icon(Icons.password, size: 18),
                label: const Text('Hash Password'),
              ),
              FilledButton.tonalIcon(
                onPressed: _argon2idVerify,
                icon: const Icon(Icons.verified, size: 18),
                label: const Text('Verify Password'),
              ),
              OutlinedButton.icon(
                onPressed: _argon2idWrongPassword,
                icon: const Icon(Icons.block, size: 18),
                label: const Text('Wrong Password'),
              ),
            ],
          ),
          const SizedBox(height: 16),

          if (_argon2idError != null) ResultCard.error(_argon2idError!),
          if (_argon2idHashResult.isNotEmpty) ...[
            HexDisplay(label: 'Argon2id PHC String', hexString: _argon2idHashResult),
          ],
          if (_argon2idVerifyResult != null) ...[
            const SizedBox(height: 12),
            _argon2idVerifyOk == true
                ? ResultCard.success(_argon2idVerifyResult!)
                : ResultCard.error(_argon2idVerifyResult!),
          ],

          const SizedBox(height: 32),
        ],
      ),
    );
  }
}
