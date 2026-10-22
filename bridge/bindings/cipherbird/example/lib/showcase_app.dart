import 'package:cipherbird_example/showcase_home.dart';
import 'package:flutter/material.dart';

/// Every capability of CipherBird, one section per screen, run live on
/// the platform the app is on.
final class ShowcaseApp extends StatelessWidget {
  const ShowcaseApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'CipherBird showcase',
    theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
    home: const ShowcaseHome(),
  );
}
