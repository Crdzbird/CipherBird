part of 'web_platform.dart';

/// The production [CipherBirdRunner] in the browser: jobs whose cost reaches
/// [inlineThreshold] run in a dedicated web worker that hosts its own copy of
/// the engine, so the page stays responsive. Closures cannot cross into a
/// worker, so [runHeavy] runs on the calling thread.
final class CipherBirdIsolateRunner implements CipherBirdRunner {
  /// Creates the runner; jobs under [inlineThreshold] cost stay inline.
  const CipherBirdIsolateRunner({this.inlineThreshold = 2048});

  /// Cost below which [run] executes inline.
  final int inlineThreshold;

  @override
  Future<R> run<R>(CipherBirdJob<R> job) async {
    if (job.cost < inlineThreshold) {
      return job.execute();
    }
    final worker = await EngineWorker.start();
    return job.decode(await worker.call(job.op, job.arguments));
  }

  @override
  Future<R> runHeavy<R>(FutureOr<R> Function() task) async => task();
}
