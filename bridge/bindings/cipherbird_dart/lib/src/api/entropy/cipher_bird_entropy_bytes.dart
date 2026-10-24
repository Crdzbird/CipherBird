part of '../../cipher_bird.dart';

/// Media entropy on bytes: a photo, a recording or any buffer held in
/// memory as the source, on every platform including the browser.
extension CipherBirdEntropyBytes on CipherBird {
  /// [entropyFromFileWithPolicy] on bytes; free the handle with
  /// [entropyFree]. [extension] only names the scratch file.
  Pointer<Void> entropyFromBytes(
    Uint8List bytes, {
    bool deterministic = false,
    double minBitsPerByte = 1.0,
    bool requireRct = true,
    String extension = 'bin',
  }) => _withScratch(
    (s) => entropyFromFileWithPolicy(
      s.put(extension, bytes),
      deterministic: deterministic,
      minBitsPerByte: minBitsPerByte,
      requireRct: requireRct,
    ),
  );

  /// [assessFileHealth] on bytes.
  HealthReport assessHealthOf(
    Uint8List bytes, {
    int maxBytes = 1 << 20,
    double floorBitsPerByte = 1.0,
  }) => _withScratch(
    (s) => assessFileHealth(
      s.put('bin', bytes),
      maxBytes: maxBytes,
      floorBitsPerByte: floorBitsPerByte,
    ),
  );

  /// [keyFromFile] on bytes: a 32-byte key from any buffer.
  Uint8List keyFromBytes(Uint8List bytes) =>
      _withScratch((s) => keyFromFile(s.put('bin', bytes)));

  /// [sealFromFile] on bytes: encrypt [plaintext] with [bytes] as the key.
  Packet sealWithBytes(Uint8List bytes, String plaintext, String aad) =>
      _withScratch((s) => sealFromFile(s.put('bin', bytes), plaintext, aad));

  /// [openFromFile] on bytes.
  Uint8List openWithBytes(Uint8List bytes, Packet packet, String aad) =>
      _withScratch((s) => openFromFile(s.put('bin', bytes), packet, aad));
}
