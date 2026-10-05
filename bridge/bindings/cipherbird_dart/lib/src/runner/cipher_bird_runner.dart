part of '../cipher_bird.dart';

/// Off-thread execution seam for heavy work (library warm-up, Argon2id).
///
/// Production uses [CipherBirdIsolateRunner]; tests use [CipherBirdInlineRunner]
/// so behaviour stays deterministic. [run] takes a top-level or static
/// function with a sendable message; [runHeavy] takes a closure that builds
/// its own native state inside the worker.
abstract interface class CipherBirdRunner {
  /// Runs [task] with [message] off-thread once [cost] reaches the runner's threshold.
  Future<R> run<M, R>(
    FutureOr<R> Function(M message) task,
    M message, {
    int cost,
  });

  /// Runs [task] off-thread as a closure.
  Future<R> runHeavy<R>(FutureOr<R> Function() task);
}
