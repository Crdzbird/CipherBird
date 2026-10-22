import 'package:cipherbird_example/play/live/live_meter_state.dart';
import 'package:flutter/material.dart';

/// Draws one bar per chunk: height is bits of min-entropy per byte out of
/// eight, green when credited, red when the policy refused it.
final class LiveMeterPainter extends CustomPainter {
  const LiveMeterPainter(this.state, this.credited, this.refused, this.grid);

  final LiveMeterState state;
  final Color credited;
  final Color refused;
  final Color grid;

  @override
  void paint(Canvas canvas, Size size) {
    final line = Paint()
      ..color = grid
      ..strokeWidth = 1;
    for (final bits in [1.0, 4.0, 8.0]) {
      final y = size.height - size.height * bits / 8;
      canvas.drawLine(Offset(0, y), Offset(size.width, y), line);
    }
    final slot = size.width / LiveMeterState.keep;
    final paint = Paint();
    for (var i = 0; i < state.bars.length; i++) {
      final (bits, ok) = state.bars[i];
      paint.color = ok ? credited : refused;
      final h = size.height * (bits.clamp(0, 8) / 8);
      final x = i * slot;
      canvas.drawRect(
        Rect.fromLTWH(x + 1, size.height - h, slot - 2, h),
        paint,
      );
    }
  }

  @override
  bool shouldRepaint(LiveMeterPainter old) => old.state != state;
}
