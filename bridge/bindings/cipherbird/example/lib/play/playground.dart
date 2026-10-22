import 'package:cipherbird_example/play/play_action.dart';
import 'package:cipherbird_example/play/play_choice.dart';
import 'package:cipherbird_example/play/play_field.dart';
import 'package:cipherbird_example/play/play_picture.dart';
import 'package:flutter/foundation.dart';

/// Fields the developer edits, actions that run the library on them, and
/// a log of what happened. Every subclass is one capability.
abstract class Playground extends ChangeNotifier {
  String get title;
  String get blurb;
  List<PlayField> get fields;
  List<PlayAction> get actions;

  /// Pick-one settings shown under the fields.
  List<PlayChoice> get choices => const [];

  /// Images shown above the log.
  List<PlayPicture> get pictures => const [];

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

  /// Runs [op] where there is a file system; the browser has none.
  Future<void> attemptWithFiles(String what, Future<void> Function() op) {
    if (kIsWeb) {
      say('$what: unsupported in the browser, there is no file system');
      return Future<void>.value();
    }
    return attempt(what, op);
  }

  /// A short printable form of a long value.
  static String brief(String s) => s.length <= 48
      ? s
      : '${s.substring(0, 24)}...${s.substring(s.length - 16)} (${s.length} chars)';

  /// The message of a refusal without its exception type.
  static String reason(Object e) => e.toString().replaceFirst(
    RegExp('^(Exception|StateError|ArgumentError|Bad state): '),
    '',
  );
}
