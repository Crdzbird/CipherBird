import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:flutter/material.dart';

import 'cryptolib_ffi.dart';

void main() {
  runApp(const CryptoLibApp());
}

class CryptoLibApp extends StatelessWidget {
  const CryptoLibApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CryptoLib Example',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorSchemeSeed: Colors.indigo,
        useMaterial3: true,
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        colorSchemeSeed: Colors.indigo,
        useMaterial3: true,
        brightness: Brightness.dark,
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  String? _version;
  String? _initError;

  String? _hashInput;
  String? _hashOutput;

  Uint8List? _symKey;
  String? _plaintext;
  Uint8List? _ciphertext;
  String? _decrypted;
  String? _roundTripStatus;

  String? _platformLabel;

  @override
  void initState() {
    super.initState();
    _platformLabel = () {
      if (Platform.isIOS)     return 'iOS (arm64, XCFramework embedded)';
      if (Platform.isAndroid) return 'Android (arm64-v8a, libcryptolib_c.so in jniLibs)';
      if (Platform.isMacOS)   return 'macOS (libcryptolib_c.dylib)';
      return Platform.operatingSystem;
    }();

    try {
      CryptoLib.init();
      setState(() => _version = CryptoLib.version());
      // Auto-run both demos at startup so the screen shows real crypto output
      // without needing the user to tap (useful for headless runs on
      // CI/simulator where we can't synthesise touches).
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _runHash();
        _runEncryptRoundTrip();
      });
    } catch (e) {
      setState(() => _initError = e.toString());
    }
  }

  void _runHash() {
    const msg = 'The quick brown fox jumps over the lazy dog';
    final digest = CryptoLib.blake2b(Uint8List.fromList(utf8.encode(msg)));
    setState(() {
      _hashInput = msg;
      _hashOutput = toHex(digest);
    });
  }

  void _runEncryptRoundTrip() {
    const msg = 'Hello from the CryptoLib FFI on this platform!';
    final key = CryptoLib.symKeygen();
    final pt = Uint8List.fromList(utf8.encode(msg));
    final ct = CryptoLib.xchaEncrypt(pt, key);
    final recovered = CryptoLib.xchaDecrypt(ct, key);
    final match = CryptoLib.secureEqual(pt, recovered);
    setState(() {
      _symKey = key;
      _plaintext = msg;
      _ciphertext = ct;
      _decrypted = utf8.decode(recovered);
      _roundTripStatus = match ? 'PASS' : 'FAIL';
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: Text('CryptoLib on ${_shortPlatform()}'),
        backgroundColor: theme.colorScheme.primaryContainer,
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            _StatusCard(
              platform: _platformLabel ?? '?',
              version: _version,
              error: _initError,
            ),
            const SizedBox(height: 16),
            _DemoCard(
              title: '1. BLAKE2b hash',
              subtitle:
                  'Hash a fixed string via the native library and display '
                  'the 64-byte digest as hex. Proves hashing works on this platform.',
              buttonLabel: 'Run BLAKE2b',
              onPressed: _runHash,
              child: _hashOutput == null
                  ? null
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        _Label(label: 'Input', value: _hashInput!),
                        const SizedBox(height: 4),
                        _Label(label: 'Digest (hex)', value: _hashOutput!, mono: true),
                      ],
                    ),
            ),
            const SizedBox(height: 16),
            _DemoCard(
              title: '2. XChaCha20-Poly1305 round-trip',
              subtitle:
                  'Generate a 32-byte key, encrypt a plaintext, decrypt it, '
                  'and verify the result matches via constant-time compare.',
              buttonLabel: 'Encrypt + Decrypt',
              onPressed: _runEncryptRoundTrip,
              child: _roundTripStatus == null
                  ? null
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        _Label(label: 'Key (32 B)', value: toHex(_symKey!), mono: true),
                        const SizedBox(height: 4),
                        _Label(label: 'Plaintext', value: _plaintext!),
                        const SizedBox(height: 4),
                        _Label(
                          label: 'Ciphertext (${_ciphertext!.length} B)',
                          value: toHex(_ciphertext!),
                          mono: true,
                        ),
                        const SizedBox(height: 4),
                        _Label(label: 'Decrypted', value: _decrypted!),
                        const SizedBox(height: 8),
                        Row(
                          children: [
                            Icon(
                              _roundTripStatus == 'PASS'
                                  ? Icons.check_circle
                                  : Icons.error,
                              color: _roundTripStatus == 'PASS'
                                  ? Colors.green
                                  : Colors.red,
                            ),
                            const SizedBox(width: 6),
                            Text(
                              'Round-trip: $_roundTripStatus',
                              style: theme.textTheme.titleMedium!.copyWith(
                                color: _roundTripStatus == 'PASS'
                                    ? Colors.green.shade700
                                    : Colors.red.shade700,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
            ),
          ],
        ),
      ),
    );
  }

  String _shortPlatform() {
    if (Platform.isIOS) return 'iOS';
    if (Platform.isAndroid) return 'Android';
    if (Platform.isMacOS) return 'macOS';
    return Platform.operatingSystem;
  }
}

class _StatusCard extends StatelessWidget {
  final String platform;
  final String? version;
  final String? error;
  const _StatusCard({required this.platform, this.version, this.error});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ok = error == null && version != null;
    return Card(
      color: ok ? Colors.green.withValues(alpha: 0.08) : Colors.red.withValues(alpha: 0.08),
      elevation: 0,
      shape: RoundedRectangleBorder(
        side: BorderSide(color: (ok ? Colors.green : Colors.red).withValues(alpha: 0.4)),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(ok ? Icons.check_circle : Icons.error,
                    color: ok ? Colors.green : Colors.red),
                const SizedBox(width: 8),
                Text(ok ? 'Native library loaded' : 'Failed to load native library',
                    style: theme.textTheme.titleMedium),
              ],
            ),
            const SizedBox(height: 6),
            _Label(label: 'Platform', value: platform),
            if (version != null) _Label(label: 'Version', value: version!, mono: true),
            if (error != null) _Label(label: 'Error', value: error!),
          ],
        ),
      ),
    );
  }
}

class _DemoCard extends StatelessWidget {
  final String title;
  final String subtitle;
  final String buttonLabel;
  final VoidCallback onPressed;
  final Widget? child;
  const _DemoCard({
    required this.title,
    required this.subtitle,
    required this.buttonLabel,
    required this.onPressed,
    this.child,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
        side: BorderSide(color: theme.colorScheme.outlineVariant),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: theme.textTheme.titleMedium),
            const SizedBox(height: 4),
            Text(subtitle, style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            )),
            const SizedBox(height: 10),
            FilledButton(onPressed: onPressed, child: Text(buttonLabel)),
            if (child != null) ...[
              const Divider(height: 24),
              child!,
            ],
          ],
        ),
      ),
    );
  }
}

class _Label extends StatelessWidget {
  final String label;
  final String value;
  final bool mono;
  const _Label({required this.label, required this.value, this.mono = false});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: theme.textTheme.labelSmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant, letterSpacing: 0.5,
          )),
          SelectableText(value,
            style: mono ? const TextStyle(fontFamily: 'Menlo', fontSize: 12)
                        : theme.textTheme.bodyMedium),
        ],
      ),
    );
  }
}
