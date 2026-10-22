import 'package:cipherbird_example/play/playground.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

/// Drives a [Playground] the way a finger would: set a field or a choice
/// by its label, press a button by its label, read what was logged.
final class PlayDriver {
  PlayDriver(this.model);

  final Playground model;

  void set(String label, String text) =>
      model.fields.singleWhere((f) => f.label == label).text = text;

  void pick(String label, String option) =>
      model.choices.singleWhere((c) => c.label == label).selected.value =
          option;

  /// Presses [label] and returns the newest log line, which is also printed.
  Future<String> press(String label) async {
    await model.actions.singleWhere((a) => a.label == label).run();
    final line = model.log.isEmpty ? '' : model.log.first;
    debugPrint('play ${model.title} / $label: $line');
    return line;
  }

  /// Presses [label] and checks the newest line contains [needle].
  Future<void> expectLine(String label, String needle) async {
    expect(await press(label), contains(needle), reason: label);
  }
}
