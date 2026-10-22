part of 'live_playground.dart';

extension on LivePlayground {
  static const int _chunk = 64 * 1024;

  String _describe(LiveFeedReport r, String what) =>
      '$what: ${r.accepted ? 'credited' : 'not credited'} '
      '${r.creditedBits.toStringAsFixed(0)} bits '
      '(${r.minEntropyPerByte.toStringAsFixed(2)} bits/byte, longest run '
      '${r.longestRun} of cutoff ${r.rctCutoff}); total '
      '${r.creditedBitsTotal.toStringAsFixed(0)} bits, '
      '${r.ready ? 'ready' : 'not ready'}'
      '${r.reason.isEmpty ? '' : '\n${r.reason}'}';

  Future<void> pickFile() => attempt('pick', () async {
    final p = await pickMedia();
    if (p == null) {
      say('no file picked');
      return;
    }
    _picked = p;
    say('picked ${p.name}: ${p.bytes.length} bytes; press Stream');
  });

  /// Streams the picked file, or a generated photo when none was picked,
  /// in 64 KiB chunks at twenty chunks a second, looping at the end.
  Future<void> startStream() => attempt('stream', () async {
    if (_stream != null) {
      say('already streaming');
      return;
    }
    final bytes = _picked?.bytes ?? photoPpm(512);
    final name = _picked?.name ?? 'a generated 512x512 photo';
    var offset = 0;
    var n = 0;
    _stream = Timer.periodic(const Duration(milliseconds: 50), (_) {
      final end = offset + _chunk > bytes.length
          ? bytes.length
          : offset + _chunk;
      final r = _source().feed(
        Uint8List.sublistView(bytes, offset, end),
        sourceId: 2,
      );
      n++;
      offset = end >= bytes.length ? 0 : end;
      _status.text = _describe(r, 'chunk $n of $name');
      refresh();
    });
    say('streaming $name in 64 KiB chunks');
  });

  void stopStream() {
    final t = _stream;
    _stream = null;
    if (t != null) {
      t.cancel();
      say('stream stopped');
    }
  }

  Future<void> generate() => attempt('generate', () async {
    try {
      say('generated: ${hexOf(_source().generate(32))}');
    } on Object catch (e) {
      say('refused: ${Playground.reason(e)}');
    }
  });

  Future<void> showStatus() => attempt('status', () async {
    final s = _source().status();
    say(
      'status: ${s.chunksFed} chunks fed (${s.chunksAccepted} credited, '
      '${s.chunksRejected} not), ${s.bytesFed} bytes, '
      '${s.creditedBitsTotal.toStringAsFixed(0)} credited bits in total, '
      '${s.creditedBitsSinceReseed.toStringAsFixed(0)} since the last of '
      '${s.reseeds} seedings, ${s.ready ? 'ready' : 'not ready'}'
      '${s.lastReason.isEmpty ? '' : '\nlast: ${s.lastReason}'}',
    );
  });
}
