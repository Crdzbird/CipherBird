part of 'native_platform.dart';

/// Frees an engine handle when the Dart object that owns it is collected
/// without having been closed. A `NativeFinalizer`, so the engine's free
/// function runs without re-entering Dart and also when the isolate shuts
/// down; the owner implements `Finalizable`, which keeps it alive for the
/// length of every call that uses its handle.
final class HandleFinalizer {
  /// A finalizer that calls [freeSymbol] of [library] on a forgotten handle.
  HandleFinalizer(DynamicLibrary library, String freeSymbol)
    : _finalizer = NativeFinalizer(
        library.lookup<NativeFinalizerFunction>(freeSymbol),
      );

  final NativeFinalizer _finalizer;

  /// Watches [owner]; [handle] is freed if it is collected first. [size] is
  /// the native memory the handle keeps alive, a hint for the collector.
  void attach(Finalizable owner, Pointer<Void> handle, {required int size}) =>
      _finalizer.attach(owner, handle, detach: owner, externalSize: size);

  /// Stops watching [owner], which is about to free its handle itself.
  void detach(Finalizable owner) => _finalizer.detach(owner);
}
