import 'dart:typed_data';

/// One captured frame: the luma plane that is assessed and a colour copy
/// for the preview.
final class LumaFrame {
  const LumaFrame(this.width, this.height, this.luma, this.rgba);

  final int width;
  final int height;
  final Uint8List luma;
  final Uint8List rgba;
}
