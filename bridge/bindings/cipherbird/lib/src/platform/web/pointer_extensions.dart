part of 'web_platform.dart';

Memory get _heap => WebEngine.current.memory;

/// Byte access on `Pointer<Uint8>`.
extension Uint8Pointer on Pointer<Uint8> {
  /// A live view of [length] bytes at this address.
  Uint8List asTypedList(int length) => _heap.view(address, length);

  int operator [](int index) => _heap.getU8(address + index);

  void operator []=(int index, int value) =>
      _heap.setU8(address + index, value);

  int get value => this[0];

  set value(int v) => this[0] = v;
}

/// Access on `Pointer<Size>`.
extension SizePointer on Pointer<Size> {
  int operator [](int index) => _heap.getU32(address + index * 4);

  void operator []=(int index, int value) =>
      _heap.setU32(address + index * 4, value);

  int get value => this[0];

  set value(int v) => this[0] = v;
}

/// Access on `Pointer<Int32>`.
extension Int32Pointer on Pointer<Int32> {
  int operator [](int index) => _heap.getI32(address + index * 4);

  void operator []=(int index, int value) =>
      _heap.setI32(address + index * 4, value);

  int get value => this[0];

  set value(int v) => this[0] = v;
}

/// Access on `Pointer<Uint64>`.
extension Uint64Pointer on Pointer<Uint64> {
  int operator [](int index) => _heap.getU64(address + index * 8);

  void operator []=(int index, int value) =>
      _heap.setU64(address + index * 8, value);

  int get value => this[0];

  set value(int v) => this[0] = v;
}

/// Access on pointers to pointers.
extension PointerPointer<T extends NativeType> on Pointer<Pointer<T>> {
  Pointer<T> operator [](int index) =>
      Pointer<T>._(_heap.getU32(address + index * 4));

  void operator []=(int index, Pointer<T> value) =>
      _heap.setU32(address + index * 4, value.address);

  Pointer<T> get value => this[0];

  set value(Pointer<T> v) => this[0] = v;
}

/// Struct view at a pointer.
extension StructPointer<T extends Struct> on Pointer<T> {
  T get ref => structView<T>(_heap, address);
}

/// Access on `Pointer<Uint16>`.
extension Uint16Pointer on Pointer<Uint16> {
  int operator [](int index) => _heap.getU16(address + index * 2);

  void operator []=(int index, int value) =>
      _heap.setU16(address + index * 2, value);

  int get value => this[0];

  set value(int v) => this[0] = v;
}
