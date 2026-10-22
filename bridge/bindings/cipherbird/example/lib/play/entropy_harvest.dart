part of 'entropy_playground.dart';

extension on EntropyPlayground {
  String get _name => 'source.$_ext';
  String get _path => _files.path(_name);
  String get _otherPath => _files.path('other.ppm');
  bool get _deterministic => _mode.value.startsWith('deterministic');

  /// A harvest under the policy the fields describe; the caller frees it.
  dynamic _harvest(String path) => _lib.entropyFromFileWithPolicy(
    path,
    deterministic: _deterministic,
    minBitsPerByte: double.parse(_floor.text),
    requireRct: _rct.picked('required'),
  );

  Uint8List _raw() {
    final h = _harvest(_path);
    try {
      return _lib.entropyRaw(h);
    } finally {
      _lib.entropyFree(h);
    }
  }

  Future<void> newSource() => attemptWithFiles('new source', () async {
    final bytes = _sourceBytes();
    _files.write(_name, bytes);
    _files.write('other.ppm', photoPpm(256, seed: 7));
    _picture.image.value = await previewImage(bytes, _ext);
    say('source ${_source.value}: ${bytes.length} bytes');
    await assess();
  });

  Future<void> assess() => attemptWithFiles('assess', () async {
    final h = _lib.assessFileHealth(_path);
    say(
      'health: ${h.minEntropyPerByte.toStringAsFixed(2)} bits of min-entropy '
      'per byte, longest run ${h.longestRun}, repetition-count test '
      '${h.rctPassed ? 'passed' : 'FAILED'}, adaptive-proportion test '
      '${h.aptPassed ? 'passed' : 'failed (photos often do, it is informational)'}',
    );
  });

  Future<void> harvest() => attemptWithFiles('harvest', () async {
    try {
      final h = _harvest(_path);
      try {
        final info = _lib.entropyInfo(h);
        say(
          'harvested ${_deterministic ? 'deterministically' : 'fresh'}: '
          '${info.chunksRead} chunks of ${info.fileSize} bytes, min-entropy '
          'estimate ${info.entropyBits.toStringAsFixed(0)} bits; raw 64 bytes '
          '${Playground.brief(hexOf(_lib.entropyRaw(h)))}',
        );
      } finally {
        _lib.entropyFree(h);
      }
    } on Object catch (e) {
      say('policy refused the source: ${Playground.reason(e)}');
    }
  });

  Future<void> harvestTwice() => attemptWithFiles('harvest twice', () async {
    final a = _raw();
    final b = _raw();
    say(
      same(a, b)
          ? 'two deterministic harvests agree byte for byte: the file is the key'
          : 'two fresh harvests differ: system randomness is mixed in each time',
    );
  });

  Future<void> deriveKeys() => attemptWithFiles('derive', () async {
    final h = _harvest(_path);
    try {
      final k = _lib.entropyDeriveAll(h);
      say('symmetric key ${Playground.brief(hexOf(k.symmetricKey))}');
      say('vault master  ${Playground.brief(hexOf(k.vaultMasterKey))}');
      say('signing seed  ${Playground.brief(hexOf(k.signingSeed))}');
      say('box seed      ${Playground.brief(hexOf(k.boxSeed))}');
      say('stream key    ${Playground.brief(hexOf(k.streamKey))}');
      final bundle = _lib.entropyAsymBundle(h);
      say('box public    ${Playground.brief(hexOf(bundle.boxPublic))}');
      say('sign public   ${Playground.brief(hexOf(bundle.signPublic))}');
    } finally {
      _lib.entropyFree(h);
    }
  });
}
