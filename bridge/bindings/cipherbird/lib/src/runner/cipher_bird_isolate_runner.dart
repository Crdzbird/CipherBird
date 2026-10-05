part of '../cipher_bird.dart';

/// The production [CipherBirdRunner]: a background isolate for any work whose
/// [run] cost reaches [inlineThreshold], and always for [runHeavy].
final class CipherBirdIsolateRunner implements CipherBirdRunner {
  /// Creates the runner; work under [inlineThreshold] cost stays inline.
  const CipherBirdIsolateRunner({this.inlineThreshold = 2048});

  /// Cost (payload size) below which [run] executes inline.
  final int inlineThreshold;

  @override
  Future<R> run<M, R>(
    FutureOr<R> Function(M message) task,
    M message, {
    int cost = 0,
  }) async {
    if (cost < inlineThreshold) {
      return task(message);
    }
    return Isolate.run(() => task(message));
  }

  @override
  Future<R> runHeavy<R>(FutureOr<R> Function() task) => Isolate.run(task);
}
