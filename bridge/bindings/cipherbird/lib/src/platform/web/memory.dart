part of 'web_platform.dart';

/// Little-endian scalar and byte access over a region of memory: either the
/// live WebAssembly heap or a local copy of a struct returned by value.
abstract interface class Memory {
  /// Reads an unsigned byte.
  int getU8(int address);

  /// Writes an unsigned byte.
  void setU8(int address, int value);

  /// Reads an unsigned 16-bit integer.
  int getU16(int address);

  /// Writes an unsigned 16-bit integer.
  void setU16(int address, int value);

  /// Reads an unsigned 32-bit integer.
  int getU32(int address);

  /// Writes an unsigned 32-bit integer.
  void setU32(int address, int value);

  /// Reads a signed 32-bit integer.
  int getI32(int address);

  /// Writes a signed 32-bit integer.
  void setI32(int address, int value);

  /// Reads an unsigned 64-bit integer (exact below 2^53).
  int getU64(int address);

  /// Writes an unsigned 64-bit integer (exact below 2^53).
  void setU64(int address, int value);

  /// Reads a 64-bit float.
  double getF64(int address);

  /// A live view of [length] bytes starting at [address].
  Uint8List view(int address, int length);
}
