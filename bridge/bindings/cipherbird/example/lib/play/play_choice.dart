import 'package:flutter/foundation.dart';

/// A pick-one setting of a playground, such as the carrier or the mode.
final class PlayChoice {
  PlayChoice(this.label, this.options)
    : selected = ValueNotifier<String>(options.first);

  final String label;
  final List<String> options;
  final ValueNotifier<String> selected;

  String get value => selected.value;

  bool picked(String option) => selected.value == option;
}
