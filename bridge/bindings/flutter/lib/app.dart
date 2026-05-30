import 'dart:io' show Platform;
import 'package:flutter/material.dart';
import 'cryptolib_ffi.dart';
import 'pages/hashing_page.dart';
import 'pages/encryption_page.dart';
import 'pages/asymmetric_page.dart';
import 'pages/entropy_page.dart';
import 'pages/vault_page.dart';
import 'pages/stego_page.dart';
import 'pages/advanced_page.dart';
import 'pages/lavarand_client_page.dart';

class CryptoLibApp extends StatefulWidget {
  /// Desktop: a dylib path to dlopen. Mobile: null — load the platform default.
  final String? initialLibPath;

  const CryptoLibApp({super.key, required this.initialLibPath});

  @override
  State<CryptoLibApp> createState() => _CryptoLibAppState();
}

class _CryptoLibAppState extends State<CryptoLibApp> {
  CryptoLib? _lib;
  String? _error;
  String _libPath = '';
  String _version = '';
  late TextEditingController _pathController;

  @override
  void initState() {
    super.initState();
    _libPath = widget.initialLibPath ?? '';
    _pathController = TextEditingController(text: _libPath);
    _loadLibrary(widget.initialLibPath);
  }

  @override
  void dispose() {
    _pathController.dispose();
    super.dispose();
  }

  void _loadLibrary([String? path]) {
    try {
      final lib = CryptoLib.load(path);
      lib.init();
      setState(() {
        _lib = lib;
        _version = lib.version();
        _error = null;
        _libPath = path ?? '';
      });
    } catch (e) {
      setState(() {
        _lib = null;
        _error = e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CryptoLib',
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
      themeMode: ThemeMode.system,
      home: _lib == null
          ? _buildLoadScreen()
          : _CryptoLibHome(lib: _lib!, version: _version),
    );
  }

  Widget _buildLoadScreen() {
    final isMobile = Platform.isIOS || Platform.isAndroid;
    return Scaffold(
      body: Builder(builder: (scaffoldContext) {
        return Center(
        child: Container(
          constraints: const BoxConstraints(maxWidth: 600),
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.lock_outline, size: 64),
              const SizedBox(height: 16),
              Text(
                'CryptoLib',
                style: Theme.of(scaffoldContext).textTheme.headlineLarge,
              ),
              const SizedBox(height: 8),
              Text(isMobile
                  ? 'Loading the bundled native library…'
                  : 'Enter the path to libcryptolib_c.dylib'),
              const SizedBox(height: 24),
              if (!isMobile)
                TextField(
                  controller: _pathController,
                  decoration: InputDecoration(
                    labelText: 'Library Path',
                    border: const OutlineInputBorder(),
                    suffixIcon: IconButton(
                      icon: const Icon(Icons.refresh),
                      onPressed: () => _loadLibrary(_pathController.text),
                    ),
                  ),
                  onSubmitted: (v) => _loadLibrary(v),
                ),
              if (_error != null) ...[
                const SizedBox(height: 16),
                Card(
                  color: Colors.red.shade50,
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Row(
                      children: [
                        Icon(Icons.error, color: Colors.red.shade700),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            _error!,
                            style: TextStyle(color: Colors.red.shade700),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: () =>
                    _loadLibrary(isMobile ? null : _pathController.text),
                icon: Icon(isMobile ? Icons.refresh : Icons.play_arrow),
                label: Text(isMobile ? 'Retry' : 'Load Library'),
              ),
            ],
          ),
        ),
      );
      }),
    );
  }
}

class _CryptoLibHome extends StatelessWidget {
  final CryptoLib lib;
  final String version;

  const _CryptoLibHome({required this.lib, required this.version});

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 8,
      child: Scaffold(
        appBar: AppBar(
          title: Row(
            children: [
              const Icon(Icons.lock_outline, size: 24),
              const SizedBox(width: 8),
              Text('CryptoLib $version'),
            ],
          ),
          bottom: const TabBar(
            isScrollable: true,
            tabs: [
              Tab(icon: Icon(Icons.tag), text: 'Hashing'),
              Tab(icon: Icon(Icons.vpn_key), text: 'Encryption'),
              Tab(icon: Icon(Icons.swap_horiz), text: 'Asymmetric'),
              Tab(icon: Icon(Icons.photo_camera), text: 'Media Entropy'),
              Tab(icon: Icon(Icons.security), text: 'Vault'),
              Tab(icon: Icon(Icons.hide_image), text: 'Steganography'),
              Tab(icon: Icon(Icons.science), text: 'Advanced'),
              Tab(icon: Icon(Icons.cloud), text: 'LavaRand Server'),
            ],
          ),
        ),
        body: TabBarView(
          children: [
            HashingPage(lib: lib),
            EncryptionPage(lib: lib),
            AsymmetricPage(lib: lib),
            EntropyPage(lib: lib),
            VaultPage(lib: lib),
            StegoPage(lib: lib),
            AdvancedPage(lib: lib),
            LavaRandClientPage(lib: lib),
          ],
        ),
      ),
    );
  }
}
