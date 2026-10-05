part of 'web_platform.dart';

/// Base of the generated struct views: a [Memory] plus a base offset. Field
/// accessors read and write at the wasm32 offsets recorded at build time.
abstract base class Struct extends NativeType {
  const Struct(this._memory, this._base);

  final Memory _memory;
  final int _base;
}
