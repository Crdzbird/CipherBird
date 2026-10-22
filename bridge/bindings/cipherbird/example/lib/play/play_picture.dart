import 'dart:ui' as ui;

import 'package:flutter/foundation.dart';

/// A decoded image a playground shows above its log.
final class PlayPicture {
  PlayPicture(this.label);

  final String label;
  final ValueNotifier<ui.Image?> image = ValueNotifier<ui.Image?>(null);
}
