part of 'entropy_playground.dart';

extension on EntropyPlayground {
  bool get _deterministic => _mode.value.startsWith('deterministic');

  Uint8List get _have {
    if (_bytes.isEmpty) {
      throw StateError('press New source first');
    }
    return _bytes;
  }

  /// A harvest under the policy the fields describe; the caller frees it.
  dynamic _harvest(Uint8List bytes) => _lib.entropyFromBytes(
    bytes,
    deterministic: _deterministic,
    minBitsPerByte: double.parse(_floor.text),
    requireRct: _rct.picked('required'),
    extension: _ext,
  );

  Uint8List _raw() {
    final h = _harvest(_have);
    try {
      return _lib.entropyRaw(h);
    } finally {
      _lib.entropyFree(h);
    }
  }

  Future<void> newSource() => attempt('new source', () async {
    _bytes = _sourceBytes();
    _picture.image.value = await previewImage(_bytes, _ext);
    say('source ${_source.value}: ${_bytes.length} bytes');
    await assess();
  });

  Future<void> assess() => attempt('assess', () async {
    final h = _lib.assessHealthOf(
      _have,
      floorBitsPerByte: double.parse(_floor.text),
    );
    if (h.summary.isNotEmpty) {
      say(h.summary);
      return;
    }
    say(
      'health: ${h.minEntropyPerByte.toStringAsFixed(2)} bits of min-entropy '
      'per byte, longest run ${h.longestRun}, repetition-count test '
      '${h.rctPassed ? 'passed' : 'FAILED'}, adaptive-proportion test '
      '${h.aptPassed ? 'passed' : 'failed'} (an older engine, no cutoffs)',
    );
  });

  Future<void> harvest() => attempt('harvest', () async {
    try {
      final h = _harvest(_have);
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

  Future<void> harvestTwice() => attempt('harvest twice', () async {
    final a = _raw();
    final b = _raw();
    say(
      same(a, b)
          ? 'two deterministic harvests agree byte for byte: the file is the key'
          : 'two fresh harvests differ: system randomness is mixed in each time',
    );
  });

  Future<void> deriveKeys() => attempt('derive', () async {
    final h = _harvest(_have);
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
