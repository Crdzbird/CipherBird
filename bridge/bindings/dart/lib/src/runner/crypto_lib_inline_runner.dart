part of '../../cryptolib_ffi.dart';

/// A [CryptoLibRunner] that runs everything on the current isolate.
final class CryptoLibInlineRunner implements CryptoLibRunner {
  /// Creates the inline runner.
  const CryptoLibInlineRunner();

  @override
  Future<R> run<M, R>(
    FutureOr<R> Function(M message) task,
    M message, {
    int cost = 0,
  }) async =>
      task(message);

  @override
  Future<R> runHeavy<R>(FutureOr<R> Function() task) async => task();
}
