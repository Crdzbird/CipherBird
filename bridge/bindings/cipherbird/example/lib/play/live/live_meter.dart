import 'package:cipherbird_example/play/live/live_meter_painter.dart';
import 'package:cipherbird_example/play/live/live_meter_state.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

/// The live picture of the stream: a bar per chunk, the credit filling up
/// towards the seed, and the counters.
final class LiveMeter extends StatelessWidget {
  const LiveMeter(this.state, {super.key});

  final ValueListenable<LiveMeterState> state;

  @override
  Widget build(BuildContext context) => ValueListenableBuilder<LiveMeterState>(
    valueListenable: state,
    builder: (context, s, _) {
      final scheme = Theme.of(context).colorScheme;
      final small = Theme.of(context).textTheme.labelSmall;
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('feeding: ${s.source}', style: small),
          const SizedBox(height: 4),
          SizedBox(
            height: 72,
            width: double.infinity,
            child: CustomPaint(
              painter: LiveMeterPainter(
                s,
                scheme.primary,
                scheme.error,
                scheme.outlineVariant,
              ),
            ),
          ),
          Text(
            'bars: min-entropy of each chunk, 0 to 8 bits per byte; '
            'green credited, red refused by the policy',
            style: small,
          ),
          const SizedBox(height: 8),
          LinearProgressIndicator(value: s.progress),
          const SizedBox(height: 4),
          Text(
            s.reseeds == 0
                ? 'credit towards the first seed: '
                      '${s.creditedBits.toStringAsFixed(0)} of '
                      '${s.minCredit.toStringAsFixed(0)} bits'
                : 'seeded ${s.reseeds} time${s.reseeds == 1 ? '' : 's'}; '
                      'credit towards the next reseed: '
                      '${s.creditedSinceReseed.toStringAsFixed(0)} of '
                      '${s.minCredit.toStringAsFixed(0)} bits',
            style: small,
          ),
          Text(
            '${s.chunks} chunks fed, ${s.chunks - s.rejected} credited, '
            '${s.rejected} refused, ${s.creditedBits.toStringAsFixed(0)} '
            'credited bits in total, generator '
            '${s.ready ? 'ready' : 'not ready'}',
            style: small,
          ),
          if (s.lastReason.isNotEmpty)
            Text(
              'last refusal: ${s.lastReason}',
              style: small?.copyWith(color: scheme.error),
              maxLines: 3,
              overflow: TextOverflow.ellipsis,
            ),
        ],
      );
    },
  );
}
