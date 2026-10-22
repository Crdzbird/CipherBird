part of 'stego_playground.dart';

extension on StegoPlayground {
  String get _coverName => 'cover.$_ext';
  String get _hiddenName => 'hidden.$_ext';
  String get _coverPath => _files.path(_coverName);
  String get _hiddenPath => _files.path(_hiddenName);
  String get _keyPhoto => _files.path('key.ppm');
  String get _otherPhoto => _files.path('other.ppm');
  Uint8List get _keyBytes => bytesOfHex(_key.text);
  Uint8List get _aadBytes => ascii(_aad.text);

  Future<void> _show(PlayPicture p, String name) async {
    p.image.value = await previewImage(_files.read(name), _ext);
  }

  Future<void> newCarrier() => attemptWithFiles('new carrier', () async {
    final bytes = _carrierBytes();
    _files.write(_coverName, bytes);
    _files.write('key.ppm', photoPpm(256, seed: 99));
    _files.write('other.ppm', photoPpm(256, seed: 7));
    _hidden.image.value = null;
    await _show(_cover, _coverName);
    say(
      'cover ${_carrier.value}: ${bytes.length} bytes, room for '
      '${_lib.stegoCapacity(_coverPath)} bytes of payload; a key photo '
      'and a second photo were written too',
    );
  });

  Future<void> hide() => attemptWithFiles('hide', () async {
    final pt = ascii(_secret.text);
    final c = _coverPath;
    final o = _hiddenPath;
    final clock = Stopwatch()..start();
    switch (_mode.value) {
      case 'plain':
        _lib.stegoEmbed(c, pt, o);
      case 'keyed placement':
        _lib.stegoEmbedKeyed(c, pt, o, _keyBytes);
      case 'encrypted':
        _lib.stegoEmbedEncrypted(c, pt, o, _keyBytes);
      case 'physical seal (a photo is the key)':
        _lib.physicalSeal(
          keyMediaPath: _keyPhoto,
          plaintext: pt,
          coverPath: c,
          outputPath: o,
          aad: _aadBytes,
        );
      case 'HPKE to Bob':
        _enc = _lib.hpkeStegoSeal(
          recipientPublic: _bob.publicKey,
          plaintext: pt,
          coverPath: c,
          outputPath: o,
          aad: _aadBytes,
        );
      case 'image factor (OPRF secret + reference photo)':
        _lib.imageFactorSeal(
          oprfSecretSeed: _oprfSeed,
          referenceImagePath: _keyPhoto,
          plaintext: pt,
          coverPath: c,
          outputPath: o,
          aad: _aadBytes,
        );
      default:
        _recipe
            .build(_sourceFor(right: true))
            .sealIntoCarrier(pt, coverPath: c, outputPath: o);
    }
    final moved = differingBytes(
      _files.read(_coverName),
      _files.read(_hiddenName),
    );
    await _show(_hidden, _hiddenName);
    say(
      'hidden with ${_mode.value}: ${pt.length} bytes in '
      '${clock.elapsedMilliseconds} ms, $moved carrier bytes changed',
    );
  });
}
