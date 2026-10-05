part of 'web_platform.dart';

/// [Memory] over the engine's linear memory. Every access re-reads the heap
/// from the module so memory growth never leaves a stale view behind.
final class HeapMemory implements Memory {
  HeapMemory(this._module);

  final EngineModule _module;

  Uint8List get _bytes => _module.heap.toDart;

  ByteData get _data {
    final bytes = _bytes;
    return ByteData.view(
      bytes.buffer,
      bytes.offsetInBytes,
      bytes.lengthInBytes,
    );
  }

  @override
  int getU8(int address) => _bytes[address];

  @override
  void setU8(int address, int value) => _bytes[address] = value;

  @override
  int getU16(int address) => _data.getUint16(address, Endian.little);

  @override
  void setU16(int address, int value) =>
      _data.setUint16(address, value, Endian.little);

  @override
  int getU32(int address) => _data.getUint32(address, Endian.little);

  @override
  void setU32(int address, int value) =>
      _data.setUint32(address, value, Endian.little);

  @override
  int getI32(int address) => _data.getInt32(address, Endian.little);

  @override
  void setI32(int address, int value) =>
      _data.setInt32(address, value, Endian.little);

  @override
  int getU64(int address) => getU32(address) + getU32(address + 4) * 4294967296;

  @override
  void setU64(int address, int value) {
    setU32(address, value % 4294967296);
    setU32(address + 4, value ~/ 4294967296);
  }

  @override
  double getF64(int address) => _data.getFloat64(address, Endian.little);

  @override
  Uint8List view(int address, int length) {
    final bytes = _bytes;
    return Uint8List.view(bytes.buffer, bytes.offsetInBytes + address, length);
  }
}
