import 'package:flutter/material.dart';

/// An editable input or output of a playground.
final class PlayField {
  PlayField(this.label, {String text = '', this.lines = 1})
    : controller = TextEditingController(text: text);

  final String label;
  final TextEditingController controller;
  final int lines;

  String get text => controller.text;
  set text(String v) => controller.text = v;
}
