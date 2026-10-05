import 'dart:async';

import 'package:cipherbird_dart/src/runner/cipher_bird_job.dart';

/// Off-thread execution seam for heavy work (library warm-up, Argon2id).
///
/// Production uses `CipherBirdIsolateRunner`, a background isolate natively
/// and a web worker in the browser; tests use `CipherBirdInlineRunner` so
/// behaviour stays deterministic. [run] takes a [CipherBirdJob] made of plain
/// data; [runHeavy] takes a closure that builds its own native state inside
/// the worker and is therefore isolate-only.
abstract interface class CipherBirdRunner {
  /// Runs [job] off-thread once its cost reaches the runner's threshold.
  Future<R> run<R>(CipherBirdJob<R> job);

  /// Runs [task] off-thread as a closure where the platform allows it.
  Future<R> runHeavy<R>(FutureOr<R> Function() task);
}
