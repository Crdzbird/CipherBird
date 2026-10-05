/// A unit of heavy work a `CipherBirdRunner` can move off the calling thread.
///
/// A job carries plain data only, so a runner can copy it into a background
/// isolate or post it to a web worker. [execute] performs the work with the
/// engine of the thread it runs on; [op] and [arguments] describe the same
/// work to the worker script, and [decode] turns the worker's reply into [R].
abstract base class CipherBirdJob<R> {
  const CipherBirdJob();

  /// Estimated cost, compared with the runner's inline threshold.
  int get cost;

  /// The operation name the worker script dispatches on.
  String get op;

  /// Plain values (strings, integers, byte lists) for the worker script.
  Map<String, Object?> get arguments;

  /// Performs the work synchronously on the current thread's engine.
  R execute();

  /// Converts the worker script's reply into the result.
  R decode(Object? reply);
}
