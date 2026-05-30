import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import '../cryptolib_ffi.dart';
import '../widgets/hex_display.dart';
import '../widgets/result_card.dart';

class AdvancedPage extends StatefulWidget {
  final CryptoLib lib;

  const AdvancedPage({super.key, required this.lib});

  @override
  State<AdvancedPage> createState() => _AdvancedPageState();
}

class _AdvancedPageState extends State<AdvancedPage>
    with AutomaticKeepAliveClientMixin {
  // File picker state
  String? _filePath;

  // Section 1: LavaRand Fingerprint
  String _fingerprintHex = '';
  String? _fingerprintResult;

  // Section 2: Multi-Layer Secure Message
  final _messageController = TextEditingController();
  String _mlHashHex = '';
  String _mlCiphertextHex = '';
  String _mlSignatureHex = '';
  Uint8List? _mlCiphertext;
  Uint8List? _mlSignature;
  Uint8List? _mlHash;
  String _mlDecryptedText = '';
  String? _mlError;

  // Section 3: Shared Photo Key Exchange
  String _aliceBoxPubHex = '';
  String _bobBoxPubHex = '';
  String _aliceSignPubHex = '';
  String _bobSignPubHex = '';
  String _boxDecryptedText = '';
  bool? _keysMatch;
  String? _keyExchangeError;

  // Section 4: Context-Based Access Control
  final _msgAController = TextEditingController();
  final _msgBController = TextEditingController();
  final _msgCController = TextEditingController();
  Packet? _packetA;
  Packet? _packetB;
  Packet? _packetC;
  String? _sealError;
  List<String> _openResults = [];
  List<String> _crossResults = [];

  // Section 5: Multi-Source Entropy Pool
  String? _entropyFile2;
  String? _entropyFile3;
  String _entropyKey1Hex = '';
  String _entropyKey2Hex = '';
  String _entropyKey3Hex = '';
  double _entropyBits1 = 0;
  double _entropyBits2 = 0;
  double _entropyBits3 = 0;
  String _combinedKeyHex = '';
  bool? _combinedKeyDiffers;
  String _combinedEncryptedHex = '';
  String _combinedDecryptedText = '';
  String? _entropyPoolError;

  // Section 6: Deterministic Test Vectors
  String _tvFingerprint = '';
  String _tvKeyHex = '';
  String _tvPlaintext = '';
  String _tvCiphertextPrefix = '';
  String _tvRecoveredText = '';
  bool? _tvKeysMatch;
  String? _tvError;

  // Section 7: Multi-Party Key Ceremony
  String? _aliceCeremonyFile;
  String? _bobCeremonyFile;
  String? _charlieCeremonyFile;
  String _aliceKeyHex = '';
  String _bobKeyHex = '';
  String _charlieKeyHex = '';
  String _ceremonyKeyHex = '';
  String _ceremonyEncryptedHex = '';
  List<String> _individualDecryptResults = [];
  String _ceremonyDecryptedText = '';
  String? _ceremonyError;

  @override
  bool get wantKeepAlive => true;

  @override
  void dispose() {
    _messageController.dispose();
    _msgAController.dispose();
    _msgBController.dispose();
    _msgCController.dispose();
    super.dispose();
  }

  Future<void> _pickFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select a media file for advanced demos',
    );
    if (result != null && result.files.single.path != null) {
      setState(() {
        _filePath = result.files.single.path;
        // Reset all state
        _fingerprintHex = '';
        _fingerprintResult = null;
        _mlHashHex = '';
        _mlCiphertextHex = '';
        _mlSignatureHex = '';
        _mlCiphertext = null;
        _mlSignature = null;
        _mlHash = null;
        _mlDecryptedText = '';
        _mlError = null;
        _aliceBoxPubHex = '';
        _bobBoxPubHex = '';
        _aliceSignPubHex = '';
        _bobSignPubHex = '';
        _boxDecryptedText = '';
        _keysMatch = null;
        _keyExchangeError = null;
        _packetA = null;
        _packetB = null;
        _packetC = null;
        _sealError = null;
        _openResults = [];
        _crossResults = [];
        // Section 5
        _entropyKey1Hex = '';
        _entropyKey2Hex = '';
        _entropyKey3Hex = '';
        _entropyBits1 = 0;
        _entropyBits2 = 0;
        _entropyBits3 = 0;
        _combinedKeyHex = '';
        _combinedKeyDiffers = null;
        _combinedEncryptedHex = '';
        _combinedDecryptedText = '';
        _entropyPoolError = null;
        // Section 6
        _tvFingerprint = '';
        _tvKeyHex = '';
        _tvPlaintext = '';
        _tvCiphertextPrefix = '';
        _tvRecoveredText = '';
        _tvKeysMatch = null;
        _tvError = null;
      });
    }
  }

  // ── Section 1: LavaRand Fingerprint ─────────────────────────────────────

  void _generateFingerprint() {
    if (_filePath == null) {
      setState(() => _fingerprintResult = 'error:Select a file first.');
      return;
    }

    Pointer<Void>? handle;
    try {
      handle = widget.lib.entropyFromFileDeterministic(_filePath!);
      final keys = widget.lib.entropyDeriveAll(handle);
      final fingerprint = widget.lib.blake2b(keys.symmetricKey);
      setState(() {
        _fingerprintHex = toHex(fingerprint);
        _fingerprintResult = 'generated';
      });
    } catch (e) {
      setState(() => _fingerprintResult = 'error:${e.toString()}');
    } finally {
      if (handle != null) widget.lib.entropyFree(handle);
    }
  }

  void _verifyFingerprint() {
    if (_filePath == null || _fingerprintHex.isEmpty) {
      setState(() => _fingerprintResult = 'error:Generate a fingerprint first.');
      return;
    }

    Pointer<Void>? handle;
    try {
      handle = widget.lib.entropyFromFileDeterministic(_filePath!);
      final keys = widget.lib.entropyDeriveAll(handle);
      final fingerprint = widget.lib.blake2b(keys.symmetricKey);
      final currentHex = toHex(fingerprint);
      final match = currentHex == _fingerprintHex;
      setState(() {
        _fingerprintResult = match ? 'verified' : 'mismatch';
      });
    } catch (e) {
      setState(() => _fingerprintResult = 'error:${e.toString()}');
    } finally {
      if (handle != null) widget.lib.entropyFree(handle);
    }
  }

  // ── Section 2: Multi-Layer Secure Message ───────────────────────────────

  void _sendSecureMessage() {
    if (_filePath == null) {
      setState(() => _mlError = 'Select a file first.');
      return;
    }
    final message = _messageController.text;
    if (message.isEmpty) {
      setState(() => _mlError = 'Enter a message.');
      return;
    }

    Pointer<Void>? handle;
    try {
      handle = widget.lib.entropyFromFileDeterministic(_filePath!);
      final keys = widget.lib.entropyDeriveAll(handle);

      // Step 1: BLAKE2b hash of message for integrity
      final msgBytes = utf8.encode(message);
      final hash = widget.lib.blake2b(Uint8List.fromList(msgBytes));

      // Step 2: XChaCha20 encrypt (message + hash) with symmetric key
      final payload = Uint8List.fromList([...msgBytes, ...hash]);
      final ciphertext = widget.lib.xchacha20Encrypt(payload, keys.symmetricKey);

      // Step 3: Ed25519 sign the ciphertext with signing seed
      final signKp = widget.lib.ed25519KeygenFromSeed(keys.signingSeed);
      final signature = widget.lib.ed25519Sign(ciphertext, signKp.secretKey);

      setState(() {
        _mlHash = hash;
        _mlCiphertext = ciphertext;
        _mlSignature = signature;
        _mlHashHex = toHex(hash);
        _mlCiphertextHex = toHex(ciphertext);
        _mlSignatureHex = toHex(signature);
        _mlDecryptedText = '';
        _mlError = null;
      });
    } catch (e) {
      setState(() => _mlError = e.toString());
    } finally {
      if (handle != null) widget.lib.entropyFree(handle);
    }
  }

  void _verifyAndDecrypt() {
    if (_filePath == null || _mlCiphertext == null || _mlSignature == null) {
      setState(() => _mlError = 'Send a secure message first.');
      return;
    }

    Pointer<Void>? handle;
    try {
      handle = widget.lib.entropyFromFileDeterministic(_filePath!);
      final keys = widget.lib.entropyDeriveAll(handle);

      // Step 1: Verify Ed25519 signature
      final signKp = widget.lib.ed25519KeygenFromSeed(keys.signingSeed);
      final sigValid = widget.lib.ed25519Verify(
        _mlCiphertext!,
        _mlSignature!,
        signKp.publicKey,
      );
      if (!sigValid) {
        setState(() => _mlError = 'Signature verification FAILED.');
        return;
      }

      // Step 2: Decrypt
      final payload = widget.lib.xchacha20Decrypt(_mlCiphertext!, keys.symmetricKey);

      // Step 3: Verify BLAKE2b hash
      // Hash is the last 32 bytes (BLAKE2b default output)
      final hashLen = 32;
      final msgBytes = payload.sublist(0, payload.length - hashLen);
      final embeddedHash = payload.sublist(payload.length - hashLen);
      final recomputedHash = widget.lib.blake2b(msgBytes);
      final hashMatch = widget.lib.secureEqual(embeddedHash, recomputedHash);

      if (!hashMatch) {
        setState(() => _mlError = 'Integrity check FAILED: hash mismatch.');
        return;
      }

      setState(() {
        _mlDecryptedText = utf8.decode(msgBytes);
        _mlError = null;
      });
    } catch (e) {
      setState(() => _mlError = e.toString());
    } finally {
      if (handle != null) widget.lib.entropyFree(handle);
    }
  }

  // ── Section 3: Shared Photo Key Exchange ────────────────────────────────

  void _simulateKeyExchange() {
    if (_filePath == null) {
      setState(() => _keyExchangeError = 'Select a file first.');
      return;
    }

    Pointer<Void>? aliceHandle;
    Pointer<Void>? bobHandle;
    try {
      // Both Alice and Bob derive keys from the same file (deterministic)
      aliceHandle = widget.lib.entropyFromFileDeterministic(_filePath!);
      final aliceBundle = widget.lib.entropyAsymBundle(aliceHandle);

      bobHandle = widget.lib.entropyFromFileDeterministic(_filePath!);
      final bobBundle = widget.lib.entropyAsymBundle(bobHandle);

      final boxMatch = widget.lib.secureEqual(aliceBundle.boxPublic, bobBundle.boxPublic);
      final signMatch = widget.lib.secureEqual(aliceBundle.signPublic, bobBundle.signPublic);

      // Alice encrypts a message with Box for Bob
      const testMessage = 'Hello Bob, this is Alice using our shared photo!';
      final msgBytes = Uint8List.fromList(utf8.encode(testMessage));
      final boxCipher = widget.lib.boxEncrypt(
        msgBytes,
        bobBundle.boxPublic,
        aliceBundle.boxSecret,
      );

      // Bob decrypts
      final decrypted = widget.lib.boxDecrypt(
        boxCipher,
        aliceBundle.boxPublic,
        bobBundle.boxSecret,
      );

      setState(() {
        _aliceBoxPubHex = toHex(aliceBundle.boxPublic);
        _bobBoxPubHex = toHex(bobBundle.boxPublic);
        _aliceSignPubHex = toHex(aliceBundle.signPublic);
        _bobSignPubHex = toHex(bobBundle.signPublic);
        _keysMatch = boxMatch && signMatch;
        _boxDecryptedText = utf8.decode(decrypted);
        _keyExchangeError = null;
      });
    } catch (e) {
      setState(() => _keyExchangeError = e.toString());
    } finally {
      if (aliceHandle != null) widget.lib.entropyFree(aliceHandle);
      if (bobHandle != null) widget.lib.entropyFree(bobHandle);
    }
  }

  // ── Section 4: Context-Based Access Control ─────────────────────────────

  void _sealForThreeUsers() {
    if (_filePath == null) {
      setState(() => _sealError = 'Select a file first.');
      return;
    }
    final msgA = _msgAController.text;
    final msgB = _msgBController.text;
    final msgC = _msgCController.text;
    if (msgA.isEmpty || msgB.isEmpty || msgC.isEmpty) {
      setState(() => _sealError = 'Enter all three messages.');
      return;
    }

    try {
      final pktA = widget.lib.sealFromFile(_filePath!, msgA, 'user-alice');
      final pktB = widget.lib.sealFromFile(_filePath!, msgB, 'user-bob');
      final pktC = widget.lib.sealFromFile(_filePath!, msgC, 'user-charlie');
      setState(() {
        _packetA = pktA;
        _packetB = pktB;
        _packetC = pktC;
        _sealError = null;
        _openResults = [];
        _crossResults = [];
      });
    } catch (e) {
      setState(() => _sealError = e.toString());
    }
  }

  void _openAsCorrectUser() {
    if (_filePath == null || _packetA == null) {
      setState(() => _sealError = 'Seal messages first.');
      return;
    }

    final results = <String>[];
    try {
      final ptA = widget.lib.openFromFile(_filePath!, _packetA!, 'user-alice');
      results.add('Alice: ${utf8.decode(ptA)}');
    } catch (e) {
      results.add('Alice: FAILED - $e');
    }
    try {
      final ptB = widget.lib.openFromFile(_filePath!, _packetB!, 'user-bob');
      results.add('Bob: ${utf8.decode(ptB)}');
    } catch (e) {
      results.add('Bob: FAILED - $e');
    }
    try {
      final ptC = widget.lib.openFromFile(_filePath!, _packetC!, 'user-charlie');
      results.add('Charlie: ${utf8.decode(ptC)}');
    } catch (e) {
      results.add('Charlie: FAILED - $e');
    }
    setState(() {
      _openResults = results;
      _sealError = null;
    });
  }

  void _crossUserAttempt() {
    if (_filePath == null || _packetA == null) {
      setState(() => _sealError = 'Seal messages first.');
      return;
    }

    final results = <String>[];

    // Try to open Alice's packet with Bob's context
    try {
      final pt = widget.lib.openFromFile(_filePath!, _packetA!, 'user-bob');
      results.add("Alice's msg with Bob's context: ${utf8.decode(pt)}");
    } catch (e) {
      results.add("Alice's msg with Bob's context: REJECTED");
    }

    // Try to open Bob's packet with Charlie's context
    try {
      final pt = widget.lib.openFromFile(_filePath!, _packetB!, 'user-charlie');
      results.add("Bob's msg with Charlie's context: ${utf8.decode(pt)}");
    } catch (e) {
      results.add("Bob's msg with Charlie's context: REJECTED");
    }

    // Try to open Charlie's packet with Alice's context
    try {
      final pt = widget.lib.openFromFile(_filePath!, _packetC!, 'user-alice');
      results.add("Charlie's msg with Alice's context: ${utf8.decode(pt)}");
    } catch (e) {
      results.add("Charlie's msg with Alice's context: REJECTED");
    }

    setState(() {
      _crossResults = results;
      _sealError = null;
    });
  }

  // ── Section 5: Multi-Source Entropy Pool ────────────────────────────────

  Future<void> _pickEntropyFile2() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select Source File 2',
    );
    if (result != null && result.files.single.path != null) {
      setState(() => _entropyFile2 = result.files.single.path);
    }
  }

  Future<void> _pickEntropyFile3() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select Source File 3',
    );
    if (result != null && result.files.single.path != null) {
      setState(() => _entropyFile3 = result.files.single.path);
    }
  }

  void _combineEntropySources() {
    if (_filePath == null || _entropyFile2 == null || _entropyFile3 == null) {
      setState(() => _entropyPoolError = 'Select all three source files first.');
      return;
    }

    Pointer<Void>? h1;
    Pointer<Void>? h2;
    Pointer<Void>? h3;
    Pointer<Void>? hCombined;
    try {
      // Derive individual keys and entropy info
      h1 = widget.lib.entropyFromFileDeterministic(_filePath!);
      final info1 = widget.lib.entropyInfo(h1);
      final keys1 = widget.lib.entropyDeriveAll(h1);

      h2 = widget.lib.entropyFromFileDeterministic(_entropyFile2!);
      final info2 = widget.lib.entropyInfo(h2);
      final keys2 = widget.lib.entropyDeriveAll(h2);

      h3 = widget.lib.entropyFromFileDeterministic(_entropyFile3!);
      final info3 = widget.lib.entropyInfo(h3);
      final keys3 = widget.lib.entropyDeriveAll(h3);

      // Combine using entropyFromFilesDeterministic
      hCombined = widget.lib.entropyFromFilesDeterministic(
        [_filePath!, _entropyFile2!, _entropyFile3!],
      );
      final combinedKeys = widget.lib.entropyDeriveAll(hCombined);
      final combinedKeyHex = toHex(combinedKeys.symmetricKey);

      final key1Hex = toHex(keys1.symmetricKey);
      final key2Hex = toHex(keys2.symmetricKey);
      final key3Hex = toHex(keys3.symmetricKey);

      // Verify combined key differs from all individual keys
      final differs = combinedKeyHex != key1Hex &&
          combinedKeyHex != key2Hex &&
          combinedKeyHex != key3Hex;

      // Encrypt/decrypt with combined key to verify it works
      const testMsg = 'Multi-source entropy pool verification message';
      final msgBytes = Uint8List.fromList(utf8.encode(testMsg));
      final ciphertext = widget.lib.xchacha20Encrypt(
        msgBytes,
        combinedKeys.symmetricKey,
      );
      final decrypted = widget.lib.xchacha20Decrypt(
        ciphertext,
        combinedKeys.symmetricKey,
      );

      setState(() {
        _entropyKey1Hex = key1Hex;
        _entropyKey2Hex = key2Hex;
        _entropyKey3Hex = key3Hex;
        _entropyBits1 = info1.entropyBits;
        _entropyBits2 = info2.entropyBits;
        _entropyBits3 = info3.entropyBits;
        _combinedKeyHex = combinedKeyHex;
        _combinedKeyDiffers = differs;
        _combinedEncryptedHex = toHex(ciphertext);
        _combinedDecryptedText = utf8.decode(decrypted);
        _entropyPoolError = null;
      });
    } catch (e) {
      setState(() => _entropyPoolError = e.toString());
    } finally {
      if (h1 != null) widget.lib.entropyFree(h1);
      if (h2 != null) widget.lib.entropyFree(h2);
      if (h3 != null) widget.lib.entropyFree(h3);
      if (hCombined != null) widget.lib.entropyFree(hCombined);
    }
  }

  // ── Section 6: Deterministic Test Vectors ─────────────────────────────

  void _generateTestVector() {
    if (_filePath == null) {
      setState(() => _tvError = 'Select a file first.');
      return;
    }

    Pointer<Void>? h1;
    Pointer<Void>? h2;
    try {
      // Derive key twice from the same file (deterministic)
      h1 = widget.lib.entropyFromFileDeterministic(_filePath!);
      final keys1 = widget.lib.entropyDeriveAll(h1);

      h2 = widget.lib.entropyFromFileDeterministic(_filePath!);
      final keys2 = widget.lib.entropyDeriveAll(h2);

      // Verify both derivations match
      final match = widget.lib.secureEqual(keys1.symmetricKey, keys2.symmetricKey);

      // Encrypt known plaintext with first key
      const knownPlaintext = 'CryptoLib test vector v1';
      final ptBytes = Uint8List.fromList(utf8.encode(knownPlaintext));
      final ciphertext = widget.lib.xchacha20Encrypt(ptBytes, keys1.symmetricKey);

      // Decrypt with second key
      final decrypted = widget.lib.xchacha20Decrypt(ciphertext, keys2.symmetricKey);
      final recoveredText = utf8.decode(decrypted);

      // File fingerprint (BLAKE2b of derived key)
      final fingerprint = widget.lib.blake2b(keys1.symmetricKey);

      setState(() {
        _tvFingerprint = toHex(fingerprint);
        _tvKeyHex = toHex(keys1.symmetricKey);
        _tvPlaintext = knownPlaintext;
        _tvCiphertextPrefix = toHex(ciphertext).length >= 32
            ? toHex(ciphertext).substring(0, 32)
            : toHex(ciphertext);
        _tvRecoveredText = recoveredText;
        _tvKeysMatch = match;
        _tvError = null;
      });
    } catch (e) {
      setState(() => _tvError = e.toString());
    } finally {
      if (h1 != null) widget.lib.entropyFree(h1);
      if (h2 != null) widget.lib.entropyFree(h2);
    }
  }

  // ── Section 7: Multi-Party Key Ceremony ───────────────────────────────

  Future<void> _pickAliceCeremonyFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select Alice\'s File',
    );
    if (result != null && result.files.single.path != null) {
      setState(() => _aliceCeremonyFile = result.files.single.path);
    }
  }

  Future<void> _pickBobCeremonyFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select Bob\'s File',
    );
    if (result != null && result.files.single.path != null) {
      setState(() => _bobCeremonyFile = result.files.single.path);
    }
  }

  Future<void> _pickCharlieCeremonyFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select Charlie\'s File',
    );
    if (result != null && result.files.single.path != null) {
      setState(() => _charlieCeremonyFile = result.files.single.path);
    }
  }

  Uint8List? _ceremonyKey;
  Uint8List? _ceremonyCiphertext;
  Uint8List? _aliceSymKey;
  Uint8List? _bobSymKey;
  Uint8List? _charlieSymKey;

  void _runCeremony() {
    if (_aliceCeremonyFile == null ||
        _bobCeremonyFile == null ||
        _charlieCeremonyFile == null) {
      setState(() => _ceremonyError = 'Select all three participant files.');
      return;
    }

    Pointer<Void>? hAlice;
    Pointer<Void>? hBob;
    Pointer<Void>? hCharlie;
    Pointer<Void>? hCombined;
    try {
      // Derive individual keys
      hAlice = widget.lib.entropyFromFileDeterministic(_aliceCeremonyFile!);
      final aliceKeys = widget.lib.entropyDeriveAll(hAlice);

      hBob = widget.lib.entropyFromFileDeterministic(_bobCeremonyFile!);
      final bobKeys = widget.lib.entropyDeriveAll(hBob);

      hCharlie = widget.lib.entropyFromFileDeterministic(_charlieCeremonyFile!);
      final charlieKeys = widget.lib.entropyDeriveAll(hCharlie);

      // Combine all 3 (concatenate raw entropy -> BLAKE2b)
      final concatenated = Uint8List.fromList([
        ...aliceKeys.rawEntropy,
        ...bobKeys.rawEntropy,
        ...charlieKeys.rawEntropy,
      ]);
      final ceremonyKey = widget.lib.blake2b(concatenated);

      // Encrypt a "Master Secret" with the ceremony key
      const masterSecret = 'TOP SECRET: Launch codes alpha-bravo-7749';
      final secretBytes = Uint8List.fromList(utf8.encode(masterSecret));
      final ciphertext = widget.lib.xchacha20Encrypt(secretBytes, ceremonyKey);

      setState(() {
        _aliceKeyHex = toHex(aliceKeys.symmetricKey);
        _bobKeyHex = toHex(bobKeys.symmetricKey);
        _charlieKeyHex = toHex(charlieKeys.symmetricKey);
        _ceremonyKeyHex = toHex(ceremonyKey);
        _ceremonyEncryptedHex = toHex(ciphertext);
        _ceremonyKey = ceremonyKey;
        _ceremonyCiphertext = ciphertext;
        _aliceSymKey = aliceKeys.symmetricKey;
        _bobSymKey = bobKeys.symmetricKey;
        _charlieSymKey = charlieKeys.symmetricKey;
        _individualDecryptResults = [];
        _ceremonyDecryptedText = '';
        _ceremonyError = null;
      });
    } catch (e) {
      setState(() => _ceremonyError = e.toString());
    } finally {
      if (hAlice != null) widget.lib.entropyFree(hAlice);
      if (hBob != null) widget.lib.entropyFree(hBob);
      if (hCharlie != null) widget.lib.entropyFree(hCharlie);
      if (hCombined != null) widget.lib.entropyFree(hCombined);
    }
  }

  void _tryIndividualDecrypt() {
    if (_ceremonyCiphertext == null) {
      setState(() => _ceremonyError = 'Run the ceremony first.');
      return;
    }

    final results = <String>[];
    final keys = {
      'Alice': _aliceSymKey!,
      'Bob': _bobSymKey!,
      'Charlie': _charlieSymKey!,
    };

    for (final entry in keys.entries) {
      try {
        widget.lib.xchacha20Decrypt(_ceremonyCiphertext!, entry.value);
        results.add('${entry.key}: Decrypted (unexpected!)');
      } catch (_) {
        results.add('${entry.key}: FAILED - wrong key');
      }
    }

    setState(() {
      _individualDecryptResults = results;
      _ceremonyError = null;
    });
  }

  void _ceremonyDecrypt() {
    if (_ceremonyCiphertext == null || _ceremonyKey == null) {
      setState(() => _ceremonyError = 'Run the ceremony first.');
      return;
    }

    try {
      final decrypted = widget.lib.xchacha20Decrypt(
        _ceremonyCiphertext!,
        _ceremonyKey!,
      );
      setState(() {
        _ceremonyDecryptedText = utf8.decode(decrypted);
        _ceremonyError = null;
      });
    } catch (e) {
      setState(() => _ceremonyError = e.toString());
    }
  }

  // ── Build ───────────────────────────────────────────────────────────────

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
            'Advanced Composition Scenarios',
            style: theme.textTheme.headlineSmall,
          ),
          const SizedBox(height: 8),
          Text(
            'Real-world demos that mix hashing, encryption, signatures, '
            'key exchange, and media entropy together.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 24),

          // File picker (shared across all sections)
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
          const SizedBox(height: 24),

          // Section 1: LavaRand Fingerprint
          _buildSection1(theme),
          const SizedBox(height: 8),

          // Section 2: Multi-Layer Secure Message
          _buildSection2(theme),
          const SizedBox(height: 8),

          // Section 3: Shared Photo Key Exchange
          _buildSection3(theme),
          const SizedBox(height: 8),

          // Section 4: Context-Based Access Control
          _buildSection4(theme),
          const SizedBox(height: 8),

          // Section 5: Multi-Source Entropy Pool
          _buildSection5(theme),
          const SizedBox(height: 8),

          // Section 6: Deterministic Test Vectors
          _buildSection6(theme),
          const SizedBox(height: 8),

          // Section 7: Multi-Party Key Ceremony
          _buildSection7(theme),

          const SizedBox(height: 32),
        ],
      ),
    );
  }

  Widget _buildSection1(ThemeData theme) {
    return ExpansionTile(
      leading: const Icon(Icons.fingerprint),
      title: const Text('LavaRand Fingerprint'),
      subtitle: const Text('Derive a deterministic device fingerprint from a file'),
      childrenPadding: const EdgeInsets.all(16),
      children: [
        Text(
          'Derives a deterministic symmetric key from the file, then '
          'produces a BLAKE2b hash as the device fingerprint. Re-verifying '
          'with the same file should always match.',
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 16),
        Wrap(
          spacing: 12,
          runSpacing: 8,
          children: [
            FilledButton.icon(
              onPressed: _generateFingerprint,
              icon: const Icon(Icons.fingerprint, size: 18),
              label: const Text('Generate Fingerprint'),
            ),
            OutlinedButton.icon(
              onPressed: _fingerprintHex.isNotEmpty ? _verifyFingerprint : null,
              icon: const Icon(Icons.verified, size: 18),
              label: const Text('Verify Fingerprint'),
            ),
          ],
        ),
        const SizedBox(height: 16),
        if (_fingerprintHex.isNotEmpty)
          HexDisplay(label: 'Device Fingerprint', hexString: _fingerprintHex),
        if (_fingerprintResult == 'generated')
          ResultCard.success('Fingerprint generated successfully.'),
        if (_fingerprintResult == 'verified')
          ResultCard.success('Fingerprint MATCHES. File identity confirmed.'),
        if (_fingerprintResult == 'mismatch')
          ResultCard.error('Fingerprint MISMATCH. File has changed or is different.'),
        if (_fingerprintResult != null && _fingerprintResult!.startsWith('error:'))
          ResultCard.error(_fingerprintResult!.substring(6)),
      ],
    );
  }

  Widget _buildSection2(ThemeData theme) {
    return ExpansionTile(
      leading: const Icon(Icons.enhanced_encryption),
      title: const Text('Multi-Layer Secure Message'),
      subtitle: const Text('Hash + Encrypt + Sign, then Verify + Decrypt + Check'),
      childrenPadding: const EdgeInsets.all(16),
      children: [
        Text(
          'Composes three layers:\n'
          '1. BLAKE2b hash of the message (integrity)\n'
          '2. XChaCha20-Poly1305 encryption of message+hash (confidentiality)\n'
          '3. Ed25519 signature of the ciphertext (authenticity)',
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 16),
        TextField(
          controller: _messageController,
          decoration: const InputDecoration(
            labelText: 'Message',
            hintText: 'Enter a secret message...',
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
              onPressed: _sendSecureMessage,
              icon: const Icon(Icons.send, size: 18),
              label: const Text('Send Secure Message'),
            ),
            OutlinedButton.icon(
              onPressed: _mlCiphertext != null ? _verifyAndDecrypt : null,
              icon: const Icon(Icons.lock_open, size: 18),
              label: const Text('Verify & Decrypt'),
            ),
          ],
        ),
        const SizedBox(height: 16),
        if (_mlError != null) ResultCard.error(_mlError!),
        if (_mlHashHex.isNotEmpty) ...[
          HexDisplay(label: 'BLAKE2b Integrity Hash', hexString: _mlHashHex),
          const SizedBox(height: 8),
          HexDisplay(label: 'XChaCha20 Ciphertext', hexString: _mlCiphertextHex),
          const SizedBox(height: 8),
          HexDisplay(label: 'Ed25519 Signature', hexString: _mlSignatureHex),
          const SizedBox(height: 12),
        ],
        if (_mlDecryptedText.isNotEmpty)
          ResultCard.success(
            _mlDecryptedText,
            title: 'Recovered Plaintext (all 3 layers verified)',
          ),
      ],
    );
  }

  Widget _buildSection3(ThemeData theme) {
    return ExpansionTile(
      leading: const Icon(Icons.people),
      title: const Text('Shared Photo Key Exchange'),
      subtitle: const Text('Alice & Bob derive matching keys from the same file'),
      childrenPadding: const EdgeInsets.all(16),
      children: [
        Text(
          'Scenario: Alice and Bob share a secret photo (e.g. via USB, AirDrop). '
          'Both independently derive X25519 and Ed25519 key pairs from the same file '
          'using deterministic entropy. Since the file is identical, their derived '
          'public keys will match, enabling encrypted communication without any '
          'key exchange protocol.',
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: _simulateKeyExchange,
          icon: const Icon(Icons.swap_horiz, size: 18),
          label: const Text('Simulate Alice & Bob with same file'),
        ),
        const SizedBox(height: 16),
        if (_keyExchangeError != null) ResultCard.error(_keyExchangeError!),
        if (_aliceBoxPubHex.isNotEmpty) ...[
          HexDisplay(label: 'Alice Box Public Key', hexString: _aliceBoxPubHex),
          const SizedBox(height: 8),
          HexDisplay(label: 'Bob Box Public Key', hexString: _bobBoxPubHex),
          const SizedBox(height: 8),
          HexDisplay(label: 'Alice Sign Public Key', hexString: _aliceSignPubHex),
          const SizedBox(height: 8),
          HexDisplay(label: 'Bob Sign Public Key', hexString: _bobSignPubHex),
          const SizedBox(height: 12),
          if (_keysMatch == true)
            ResultCard.success(
              'Both public key pairs MATCH.\n'
              'Deterministic derivation from the same file produces identical keys.',
            )
          else if (_keysMatch == false)
            ResultCard.error('Keys do NOT match -- unexpected.'),
          if (_boxDecryptedText.isNotEmpty) ...[
            const SizedBox(height: 8),
            ResultCard.success(
              _boxDecryptedText,
              title: 'Bob decrypted Alice\'s Box message',
            ),
          ],
        ],
      ],
    );
  }

  Widget _buildSection4(ThemeData theme) {
    return ExpansionTile(
      leading: const Icon(Icons.admin_panel_settings),
      title: const Text('Context-Based Access Control'),
      subtitle: const Text('Same key, different AAD contexts isolate messages'),
      childrenPadding: const EdgeInsets.all(16),
      children: [
        Text(
          'Uses seal_from_file with different AAD (associated authenticated data) '
          'strings to create context-isolated ciphertexts. Each sealed message can '
          'only be opened with the exact same AAD context it was sealed with.',
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 16),
        TextField(
          controller: _msgAController,
          decoration: const InputDecoration(
            labelText: 'Message A (for Alice)',
            hintText: 'Alice\'s secret...',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _msgBController,
          decoration: const InputDecoration(
            labelText: 'Message B (for Bob)',
            hintText: 'Bob\'s secret...',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _msgCController,
          decoration: const InputDecoration(
            labelText: 'Message C (for Charlie)',
            hintText: 'Charlie\'s secret...',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 16),
        Wrap(
          spacing: 12,
          runSpacing: 8,
          children: [
            FilledButton.icon(
              onPressed: _sealForThreeUsers,
              icon: const Icon(Icons.lock, size: 18),
              label: const Text('Seal for 3 users'),
            ),
            OutlinedButton.icon(
              onPressed: _packetA != null ? _openAsCorrectUser : null,
              icon: const Icon(Icons.lock_open, size: 18),
              label: const Text('Open as correct user'),
            ),
            OutlinedButton.icon(
              onPressed: _packetA != null ? _crossUserAttempt : null,
              icon: const Icon(Icons.block, size: 18),
              label: const Text('Cross-user attempt'),
            ),
          ],
        ),
        const SizedBox(height: 16),
        if (_sealError != null) ResultCard.error(_sealError!),
        if (_packetA != null && _openResults.isEmpty && _crossResults.isEmpty)
          ResultCard.success(
            'Sealed 3 messages with contexts: user-alice, user-bob, user-charlie.',
          ),
        if (_openResults.isNotEmpty) ...[
          Text('Correct Context Results', style: theme.textTheme.titleSmall),
          const SizedBox(height: 8),
          for (final r in _openResults) ...[
            r.contains('FAILED')
                ? ResultCard.error(r)
                : ResultCard.success(r),
            const SizedBox(height: 4),
          ],
          const SizedBox(height: 12),
        ],
        if (_crossResults.isNotEmpty) ...[
          Text('Cross-Context Results', style: theme.textTheme.titleSmall),
          const SizedBox(height: 8),
          for (final r in _crossResults) ...[
            r.contains('REJECTED')
                ? ResultCard.success(r, title: 'Access correctly denied')
                : ResultCard.error(r, title: 'Unexpected access granted'),
            const SizedBox(height: 4),
          ],
        ],
      ],
    );
  }

  Widget _buildSection5(ThemeData theme) {
    return ExpansionTile(
      leading: const Icon(Icons.merge_type),
      title: const Text('Multi-Source Entropy Pool'),
      subtitle: const Text('Combine entropy from multiple files into one key'),
      childrenPadding: const EdgeInsets.all(16),
      children: [
        Text(
          'Derives keys from three separate files and combines them using '
          'entropyFromFilesDeterministic. The combined key differs from all '
          'individual keys. If any one source is compromised, the others '
          'still protect the key.',
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 16),
        Text(
          'Source File 1: ${_filePath ?? "Use main file picker above"}',
          style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
          overflow: TextOverflow.ellipsis,
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            OutlinedButton.icon(
              onPressed: _pickEntropyFile2,
              icon: const Icon(Icons.folder_open, size: 18),
              label: const Text('Source File 2'),
            ),
            const SizedBox(width: 12),
            if (_entropyFile2 != null)
              Expanded(
                child: Text(
                  _entropyFile2!,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
          ],
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            OutlinedButton.icon(
              onPressed: _pickEntropyFile3,
              icon: const Icon(Icons.folder_open, size: 18),
              label: const Text('Source File 3'),
            ),
            const SizedBox(width: 12),
            if (_entropyFile3 != null)
              Expanded(
                child: Text(
                  _entropyFile3!,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
          ],
        ),
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: _combineEntropySources,
          icon: const Icon(Icons.merge, size: 18),
          label: const Text('Combine Entropy Sources'),
        ),
        const SizedBox(height: 16),
        if (_entropyPoolError != null) ResultCard.error(_entropyPoolError!),
        if (_entropyKey1Hex.isNotEmpty) ...[
          HexDisplay(label: 'Key 1 (File 1)', hexString: _entropyKey1Hex),
          Text(
            'Entropy bits: ${_entropyBits1.toStringAsFixed(2)}',
            style: theme.textTheme.bodySmall,
          ),
          const SizedBox(height: 8),
          HexDisplay(label: 'Key 2 (File 2)', hexString: _entropyKey2Hex),
          Text(
            'Entropy bits: ${_entropyBits2.toStringAsFixed(2)}',
            style: theme.textTheme.bodySmall,
          ),
          const SizedBox(height: 8),
          HexDisplay(label: 'Key 3 (File 3)', hexString: _entropyKey3Hex),
          Text(
            'Entropy bits: ${_entropyBits3.toStringAsFixed(2)}',
            style: theme.textTheme.bodySmall,
          ),
          const SizedBox(height: 12),
          HexDisplay(label: 'Combined Key', hexString: _combinedKeyHex),
          const SizedBox(height: 8),
          if (_combinedKeyDiffers == true)
            ResultCard.success(
              'Combined key differs from all individual keys.\n'
              'Encrypt/decrypt verified: "$_combinedDecryptedText"',
              title: 'Multi-source entropy pool valid',
            )
          else if (_combinedKeyDiffers == false)
            ResultCard.error('Combined key unexpectedly matches an individual key.'),
          const SizedBox(height: 8),
          if (_combinedEncryptedHex.isNotEmpty)
            HexDisplay(label: 'Verification Ciphertext', hexString: _combinedEncryptedHex),
          const SizedBox(height: 8),
          Text(
            'Note: If any one source is compromised, the others still protect the key.',
            style: theme.textTheme.bodySmall?.copyWith(
              fontStyle: FontStyle.italic,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildSection6(ThemeData theme) {
    return ExpansionTile(
      leading: const Icon(Icons.science),
      title: const Text('Deterministic Test Vectors'),
      subtitle: const Text('Verify reproducible key derivation and encryption'),
      childrenPadding: const EdgeInsets.all(16),
      children: [
        Text(
          'Derives a key twice from the same file and verifies both derivations '
          'match via secure_equal. Then encrypts a known plaintext with the first '
          'key and decrypts with the second to confirm deterministic behavior.',
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: _generateTestVector,
          icon: const Icon(Icons.play_arrow, size: 18),
          label: const Text('Generate Test Vector'),
        ),
        const SizedBox(height: 16),
        if (_tvError != null) ResultCard.error(_tvError!),
        if (_tvKeyHex.isNotEmpty) ...[
          Card(
            elevation: 2,
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Test Vector Card',
                    style: theme.textTheme.titleSmall?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const Divider(),
                  const SizedBox(height: 8),
                  HexDisplay(
                    label: 'File Fingerprint (BLAKE2b of key)',
                    hexString: _tvFingerprint,
                  ),
                  const SizedBox(height: 8),
                  HexDisplay(
                    label: 'Symmetric Key',
                    hexString: _tvKeyHex,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Known Plaintext: "$_tvPlaintext"',
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  ),
                  const SizedBox(height: 8),
                  HexDisplay(
                    label: 'Ciphertext Prefix (first 32 hex chars)',
                    hexString: _tvCiphertextPrefix,
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          if (_tvKeysMatch == true)
            ResultCard.success(
              'Both derivations match (secure_equal verified).\n'
              'Recovered plaintext: "$_tvRecoveredText"\n'
              'Test vector is reproducible.',
            )
          else if (_tvKeysMatch == false)
            ResultCard.error('Derivations do NOT match -- unexpected.'),
        ],
      ],
    );
  }

  Widget _buildSection7(ThemeData theme) {
    return ExpansionTile(
      leading: const Icon(Icons.groups),
      title: const Text('Multi-Party Key Ceremony'),
      subtitle: const Text('Three parties combine entropy to protect a master secret'),
      childrenPadding: const EdgeInsets.all(16),
      children: [
        Text(
          'Alice, Bob, and Charlie each contribute a file. Individual keys are '
          'derived from each, then all raw entropy is concatenated and BLAKE2b-hashed '
          'into a ceremony key. Only the combined ceremony key can decrypt the '
          'master secret. No single party can access it alone.',
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            OutlinedButton.icon(
              onPressed: _pickAliceCeremonyFile,
              icon: const Icon(Icons.person, size: 18),
              label: const Text("Alice's File"),
            ),
            const SizedBox(width: 12),
            if (_aliceCeremonyFile != null)
              Expanded(
                child: Text(
                  _aliceCeremonyFile!,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
          ],
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            OutlinedButton.icon(
              onPressed: _pickBobCeremonyFile,
              icon: const Icon(Icons.person, size: 18),
              label: const Text("Bob's File"),
            ),
            const SizedBox(width: 12),
            if (_bobCeremonyFile != null)
              Expanded(
                child: Text(
                  _bobCeremonyFile!,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
          ],
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            OutlinedButton.icon(
              onPressed: _pickCharlieCeremonyFile,
              icon: const Icon(Icons.person, size: 18),
              label: const Text("Charlie's File"),
            ),
            const SizedBox(width: 12),
            if (_charlieCeremonyFile != null)
              Expanded(
                child: Text(
                  _charlieCeremonyFile!,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
          ],
        ),
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: _runCeremony,
          icon: const Icon(Icons.vpn_key, size: 18),
          label: const Text('Run Ceremony'),
        ),
        const SizedBox(height: 16),
        if (_ceremonyError != null) ResultCard.error(_ceremonyError!),
        if (_aliceKeyHex.isNotEmpty) ...[
          HexDisplay(label: "Alice's Individual Key", hexString: _aliceKeyHex),
          const SizedBox(height: 8),
          HexDisplay(label: "Bob's Individual Key", hexString: _bobKeyHex),
          const SizedBox(height: 8),
          HexDisplay(label: "Charlie's Individual Key", hexString: _charlieKeyHex),
          const SizedBox(height: 12),
          HexDisplay(label: 'Combined Ceremony Key', hexString: _ceremonyKeyHex),
          const SizedBox(height: 8),
          HexDisplay(label: 'Encrypted Master Secret', hexString: _ceremonyEncryptedHex),
          const SizedBox(height: 16),
          Wrap(
            spacing: 12,
            runSpacing: 8,
            children: [
              OutlinedButton.icon(
                onPressed: _ceremonyCiphertext != null ? _tryIndividualDecrypt : null,
                icon: const Icon(Icons.no_encryption, size: 18),
                label: const Text('Try Individual Decrypt'),
              ),
              FilledButton.icon(
                onPressed: _ceremonyCiphertext != null ? _ceremonyDecrypt : null,
                icon: const Icon(Icons.lock_open, size: 18),
                label: const Text('Ceremony Decrypt'),
              ),
            ],
          ),
          const SizedBox(height: 16),
          if (_individualDecryptResults.isNotEmpty) ...[
            Text('Individual Decrypt Attempts', style: theme.textTheme.titleSmall),
            const SizedBox(height: 8),
            for (final r in _individualDecryptResults) ...[
              r.contains('FAILED')
                  ? ResultCard.success(r, title: 'Correctly denied')
                  : ResultCard.error(r, title: 'Unexpected success'),
              const SizedBox(height: 4),
            ],
          ],
          if (_ceremonyDecryptedText.isNotEmpty) ...[
            const SizedBox(height: 8),
            ResultCard.success(
              _ceremonyDecryptedText,
              title: 'Master secret recovered with ceremony key',
            ),
          ],
          const SizedBox(height: 8),
          Text(
            'All 3 participants must contribute. No single party can access the master secret.',
            style: theme.textTheme.bodySmall?.copyWith(
              fontStyle: FontStyle.italic,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ],
    );
  }
}
