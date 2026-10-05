part of 'web_platform.dart';

/// [Memory] over a private copy of bytes. Structs the engine returns by value
/// are copied here so the scratch area in the heap can be released at once.
final class LocalMemory implements Memory {
  LocalMemory(this._bytes)
    : _data = ByteData.view(
        _bytes.buffer,
        _bytes.offsetInBytes,
        _bytes.lengthInBytes,
      );

  /// Copies [length] bytes at [address] out of [source].
  factory LocalMemory.copyFrom(Memory source, int address, int length) =>
      LocalMemory(Uint8List.fromList(source.view(address, length)));

  final Uint8List _bytes;
  final ByteData _data;

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
  Uint8List view(int address, int length) =>
      Uint8List.sublistView(_bytes, address, address + length);
}
