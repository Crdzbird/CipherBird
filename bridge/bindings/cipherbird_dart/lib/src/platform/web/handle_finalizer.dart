part of 'web_platform.dart';

/// Frees an engine handle when the Dart object that owns it is collected
/// without having been closed, with the call shape of the native build's
/// `HandleFinalizer`. The browser offers no finalizer that is certain to
/// run, so this one is best effort: close the object when done.
final class HandleFinalizer {
  /// A finalizer that calls [freeSymbol] of [library] on a forgotten handle.
  HandleFinalizer(DynamicLibrary library, String freeSymbol)
    : _finalizer = Finalizer<Pointer<Void>>(
        library.lookupFunction<
          void Function(Pointer<Void>),
          void Function(Pointer<Void>)
        >(freeSymbol),
      );

  final Finalizer<Pointer<Void>> _finalizer;

  /// Watches [owner]; [handle] is freed if it is collected first. [size] is
  /// accepted for symmetry with the native build.
  void attach(Finalizable owner, Pointer<Void> handle, {required int size}) =>
      _finalizer.attach(owner, handle, detach: owner);

  /// Stops watching [owner], which is about to free its handle itself.
  void detach(Finalizable owner) => _finalizer.detach(owner);
}
