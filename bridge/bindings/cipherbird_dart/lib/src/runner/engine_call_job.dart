import 'package:cipherbird_dart/src/runner/cipher_bird_job.dart';
import 'package:cipherbird_dart/src/runner/engine_reply.dart';
import 'package:cipherbird_dart/src/runner/job_arg.dart';
import 'package:cipherbird_dart/src/runner/job_return.dart';

/// A call to one engine entry point by symbol: [inline] performs it on the
/// calling thread's engine, and [symbol], [args] and [returns] describe the
/// same call to a worker that holds its own engine; see the job seam.
final class EngineCallJob<R> extends CipherBirdJob<R> {
  const EngineCallJob({
    required this.symbol,
    required this.args,
    required this.returns,
    required this.cost,
    required this.inline,
    required this.decodeReply,
  });

  final String symbol;
  final List<JobArg> args;
  final JobReturn returns;

  /// Performs the call on the calling thread's engine.
  final R Function() inline;

  /// Turns the worker's reply into the result.
  final R Function(EngineReply reply) decodeReply;

  @override
  final int cost;

  @override
  String get op => 'call';

  @override
  Map<String, Object?> get arguments => {
    'symbol': symbol,
    'ret': returns == JobReturn.int32
        ? 'int'
        : returns == JobReturn.none
        ? 'void'
        : returns.name,
    'args': [for (final a in args) a.toMap()],
  };

  @override
  R execute() => inline();

  @override
  R decode(Object? reply) => decodeReply(EngineReply.from(reply));
}
