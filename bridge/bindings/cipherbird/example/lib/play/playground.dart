import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:flutter/foundation.dart';

/// Fields the developer edits, actions that run the library on them, and
/// a log of what happened. Every subclass is one capability.
abstract class Playground extends ChangeNotifier {
  String get title;
  String get blurb;
  List<PlayField> get fields;
  List<PlayAction> get actions;

  final List<String> log = [];

  void say(String line) {
    log.insert(0, line);
    notifyListeners();
  }

  void clear() {
    log.clear();
    notifyListeners();
  }

  /// Runs [op]; a throw becomes a log line instead of a crash.
  Future<void> attempt(String what, Future<void> Function() op) async {
    try {
      await op();
    } on Object catch (e) {
      say('$what: $e');
    }
  }

  /// A short printable form of a long value.
  static String brief(String s) => s.length <= 48
      ? s
      : '${s.substring(0, 24)}...${s.substring(s.length - 16)} (${s.length} chars)';
}
