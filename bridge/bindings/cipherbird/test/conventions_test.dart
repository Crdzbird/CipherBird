@TestOn('vm')
library;

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Structure rules for lib/src: one class per file, at most `maxLines` lines
/// after `dart format`, no `else`, no inline `//` comments. The library root
/// (the part directive list) is exempt from the line limit only.
void main() {
  const scanRoot = 'lib/src';
  const maxLines = 100;
  const lineLimitExempt = {
    'lib/src/cipher_bird.dart',
    'lib/src/platform/native/native_platform.dart',
    'lib/src/platform/web/web_platform.dart',
  };
  final classPattern = RegExp(
    r'^\s*(final |abstract final |abstract interface |sealed |base |abstract )*class\s',
  );
  final elsePattern = RegExp(r'}\s*else\b|^\s*else\b');
  final inlineComment = RegExp('(^|[^:/])//(?!/)');

  test(
    'lib/src files: one class, <=$maxLines lines, no else, no // comments',
    () {
      final violations = <String>[];
      final root = Directory(scanRoot);
      if (!root.existsSync()) {
        return;
      }
      final files = root
          .listSync(recursive: true)
          .whereType<File>()
          .where((f) => f.path.endsWith('.dart'));
      for (final file in files) {
        final lines = file.readAsLinesSync();
        if (lines.length > maxLines && !lineLimitExempt.contains(file.path)) {
          violations.add('${file.path}: ${lines.length} lines (max $maxLines)');
        }
        final classCount = lines.where(classPattern.hasMatch).length;
        if (classCount > 1) {
          violations.add('${file.path}: $classCount classes (max 1)');
        }
        for (var i = 0; i < lines.length; i++) {
          if (elsePattern.hasMatch(lines[i])) {
            violations.add('${file.path}:${i + 1}: else branch');
          }
          if (inlineComment.hasMatch(lines[i]) && !lines[i].contains("'")) {
            violations.add('${file.path}:${i + 1}: inline comment');
          }
        }
      }
      expect(violations, isEmpty, reason: violations.join('\n'));
    },
  );
}
