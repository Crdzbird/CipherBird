import 'dart:typed_data';

/// One argument of an engine call job, as plain data a worker can take.
final class JobArg {
  const JobArg._(this.kind, this.value, [this.extension]);

  /// A byte buffer passed as pointer and length.
  factory JobArg.bytes(Uint8List v) => JobArg._('bytes', v);

  /// A C string.
  factory JobArg.str(String v) => JobArg._('str', v);

  /// A 32-bit integer.
  factory JobArg.i32(int v) => JobArg._('i32', v);

  /// A 64-bit integer, split for the wrapper.
  factory JobArg.u64(int v) => JobArg._('u64', v);

  /// A double.
  factory JobArg.f64(double v) => JobArg._('f64', v);

  /// Bytes written to a scratch file whose path is passed.
  factory JobArg.file(String extension, Uint8List v) =>
      JobArg._('file', v, extension);

  /// A scratch output path; the file comes back in the reply.
  factory JobArg.out(String extension) => JobArg._('out', null, extension);

  final String kind;
  final Object? value;
  final String? extension;

  Map<String, Object?> toMap() => {
    'k': kind,
    if (value != null) 'v': value,
    if (extension != null) 'ext': extension,
  };
}
