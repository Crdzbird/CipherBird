import 'dart:typed_data';

/// A file the developer chose from the device: its name and its bytes.
final class PickedMedia {
  const PickedMedia(this.name, this.bytes);

  final String name;
  final Uint8List bytes;

  /// The lower-case extension, which the engine dispatches on.
  String get extension {
    final dot = name.lastIndexOf('.');
    return dot < 0 ? 'bin' : name.substring(dot + 1).toLowerCase();
  }
}
