part of 'stego_playground.dart';

extension on StegoPlayground {
  Uint8List get _keyBytes => bytesOfHex(_key.text);
  Uint8List get _aadBytes => ascii(_aad.text);

  Future<void> _show(PlayPicture p, Uint8List bytes) async {
    p.image.value = await previewImage(bytes, _ext);
  }

  Future<void> newCarrier() => attempt('new carrier', () async {
    final bytes = _carrierBytes();
    final format = _format;
    _coverBytes = bytes;
    _hiddenBytes = Uint8List(0);
    _hidden.image.value = null;
    await _show(_cover, bytes);
    say(
      'cover ${_carrier.value}: ${bytes.length} bytes, room for '
      '${_lib.stegoCapacityOf(bytes, format)} bytes of payload; a key photo '
      'and a second photo are generated too',
    );
  });

  Future<void> hide() => attempt('hide', () async {
    final pt = ascii(_secret.text);
    final c = _coverBytes;
    final f = _format;
    final clock = Stopwatch()..start();
    _hiddenBytes = switch (_mode.value) {
      'plain' => _lib.stegoEmbedBytes(c, f, pt),
      'keyed placement' => _lib.stegoEmbedKeyedBytes(c, f, pt, _keyBytes),
      'encrypted' => _lib.stegoEmbedEncryptedBytes(c, f, pt, _keyBytes),
      'physical seal (a photo is the key)' => _lib.physicalSealBytes(
        keyMedia: _keyPhoto,
        keyMediaFormat: MediaFormat.ppmImage,
        plaintext: pt,
        cover: c,
        coverFormat: f,
        aad: _aadBytes,
      ),
      'HPKE to Bob' => _hpkeHide(pt, c, f),
      'image factor (OPRF secret + reference photo)' =>
        _lib.imageFactorSealBytes(
          oprfSecretSeed: _oprfSeed,
          referenceImage: _keyPhoto,
          referenceFormat: MediaFormat.ppmImage,
          plaintext: pt,
          cover: c,
          coverFormat: f,
          aad: _aadBytes,
        ),
      _ => _lib.stegoEmbedBytes(
        c,
        f,
        _recipe.build(_sourceFor(right: true)).seal(pt),
      ),
    };
    final moved = differingBytes(c, _hiddenBytes);
    await _show(_hidden, _hiddenBytes);
    say(
      'hidden with ${_mode.value}: ${pt.length} bytes in '
      '${clock.elapsedMilliseconds} ms, $moved carrier bytes changed',
    );
  });

  Uint8List _hpkeHide(Uint8List pt, Uint8List c, MediaFormat f) {
    final r = _lib.hpkeStegoSealBytes(
      recipientPublic: _bob.publicKey,
      plaintext: pt,
      cover: c,
      coverFormat: f,
      aad: _aadBytes,
    );
    _enc = r.enc;
    return r.carrier;
  }

  Uint8List _keyFor(bool right) => right ? _keyBytes : _lib.randomBytes(32);
}
