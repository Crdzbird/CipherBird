import 'dart:async';

import 'package:cipherbird_dart/src/runner/cipher_bird_job.dart';
import 'package:cipherbird_dart/src/runner/cipher_bird_runner.dart';

/// A [CipherBirdRunner] that runs everything on the current thread.
final class CipherBirdInlineRunner implements CipherBirdRunner {
  /// Creates the inline runner.
  const CipherBirdInlineRunner();

  @override
  Future<R> run<R>(CipherBirdJob<R> job) async => job.execute();

  @override
  Future<R> runHeavy<R>(FutureOr<R> Function() task) async => task();
}
