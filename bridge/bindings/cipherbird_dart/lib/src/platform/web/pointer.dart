part of 'web_platform.dart';

/// An address in the engine's WebAssembly linear memory, typed like a
/// dart:ffi pointer so the shared API layer compiles unchanged on the web.
@immutable
final class Pointer<T extends NativeType> extends NativeType {
  const Pointer._(this.address);

  /// Wraps a raw [address].
  const Pointer.fromAddress(this.address);

  /// The linear-memory offset this pointer refers to.
  final int address;

  /// Reinterprets the pointee type.
  Pointer<U> cast<U extends NativeType>() => Pointer<U>._(address);

  @override
  bool operator ==(Object other) =>
      other is Pointer<NativeType> && other.address == address;

  @override
  int get hashCode => address;

  @override
  String toString() => 'Pointer<$T>: address=0x${address.toRadixString(16)}';
}

/// The null pointer.
const Pointer<Never> nullptr = Pointer<Never>._(0);
