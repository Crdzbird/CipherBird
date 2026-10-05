part of 'native_platform.dart';

/// The production [CipherBirdRunner]: a background isolate for any job whose
/// cost reaches [inlineThreshold], and always for [runHeavy].
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
    return Isolate.run(job.execute);
  }

  @override
  Future<R> runHeavy<R>(FutureOr<R> Function() task) => Isolate.run(task);
}
