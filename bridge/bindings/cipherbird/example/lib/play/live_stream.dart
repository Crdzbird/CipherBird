part of 'live_playground.dart';

extension on LivePlayground {
  static const int _chunk = 64 * 1024;

  Widget previewOf() {
    final c = _camera;
    final camera = c == null || !c.value.isInitialized
        ? null
        : SizedBox(height: 180, child: CameraPreview(c));
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ValueListenableBuilder<ui.Image?>(
          valueListenable: _macFrame,
          builder: (context, img, _) => img == null
              ? const SizedBox.shrink()
              : SizedBox(height: 180, child: RawImage(image: img)),
        ),
        ?camera,
        LiveMeter(meter),
      ],
    );
  }

  void _fed(LiveFeedReport r, String source) {
    meter.value = meter.value.after(r, source, double.parse(_credit.text));
  }

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
    _stream = Timer.periodic(const Duration(milliseconds: 50), (_) {
      final end = offset + _chunk > bytes.length
          ? bytes.length
          : offset + _chunk;
      final r = _source().feed(
        Uint8List.sublistView(bytes, offset, end),
        sourceId: 2,
      );
      offset = end >= bytes.length ? 0 : end;
      _fed(r, '$name, 64 KiB chunks, 20 a second');
    });
    say('streaming $name in 64 KiB chunks; watch the meter');
  });

  void stopStream() {
    final t = _stream;
    _stream = null;
    if (t != null) {
      t.cancel();
      say('stream stopped after ${meter.value.chunks} chunks');
    }
  }

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
