import 'package:cryptolib_playground/src/playground_page.dart';
import 'package:flutter/material.dart';

final class PlaygroundApp extends StatelessWidget {
  const PlaygroundApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
    theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
    home: const PlaygroundPage(),
  );
}
