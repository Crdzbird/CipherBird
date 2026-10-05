part of 'web_platform.dart';

/// The web stand-in for the isolate runner: browsers give this package no
/// isolates, so every task runs on the calling thread.
final class CipherBirdIsolateRunner implements CipherBirdRunner {
  /// Creates the runner; [inlineThreshold] is kept for API symmetry.
  const CipherBirdIsolateRunner({this.inlineThreshold = 2048});

  /// Unused on the web.
  final int inlineThreshold;

  @override
  Future<R> run<M, R>(
    FutureOr<R> Function(M message) task,
    M message, {
    int cost = 0,
  }) async => task(message);

  @override
  Future<R> runHeavy<R>(FutureOr<R> Function() task) async => task();
}
