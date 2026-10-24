import 'dart:typed_data';

/// What a worker sent back for an engine call job: the entry point's value
/// and the bytes of every output file.
final class EngineReply {
  const EngineReply(this.value, this.files);

  factory EngineReply.from(Object? reply) {
    final m = reply! as Map<Object?, Object?>;
    final files = (m['files'] as List<Object?>? ?? const [])
        .map(asBytes)
        .toList();
    return EngineReply(m['value'], files);
  }

  final Object? value;
  final List<Uint8List> files;

  /// The value as bytes.
  Uint8List get bytes => asBytes(value);

  /// The value as a key pair, `pk` and `sk`.
  (Uint8List, Uint8List) get keyPair {
    final m = value! as Map<Object?, Object?>;
    return (asBytes(m['pk']), asBytes(m['sk']));
  }

  /// The value as an integer.
  int get int32 => (value! as num).toInt();

  /// Bytes however the message channel delivered them.
  static Uint8List asBytes(Object? v) => switch (v) {
    final Uint8List u => u,
    final ByteBuffer b => b.asUint8List(),
    final List<Object?> l => Uint8List.fromList(l.cast<int>()),
    _ => throw StateError('cipherbird: worker reply is not bytes'),
  };
}
