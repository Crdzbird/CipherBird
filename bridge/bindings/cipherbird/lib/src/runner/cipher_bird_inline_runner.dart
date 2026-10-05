import 'dart:async';

import 'package:cipherbird/src/runner/cipher_bird_runner.dart';

/// A [CipherBirdRunner] that runs everything on the current isolate.
final class CipherBirdInlineRunner implements CipherBirdRunner {
  /// Creates the inline runner.
  const CipherBirdInlineRunner();

  @override
  Future<R> run<M, R>(
    FutureOr<R> Function(M message) task,
    M message, {
    int cost = 0,
  }) async => task(message);

  @override
  Future<R> runHeavy<R>(FutureOr<R> Function() task) async => task();
}
