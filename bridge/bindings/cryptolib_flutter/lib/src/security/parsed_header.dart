part of '../cryptolib.dart';

final class _ParsedHeader {
  const _ParsedHeader({
    required this.header,
    required this.layers,
    required this.salt,
    required this.signatureId,
    required this.ops,
    required this.memory,
  });

  final Uint8List header;
  final List<ProtectionLayer> layers;
  final Uint8List salt;
  final int signatureId;
  final int ops;
  final int memory;
}
