import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/showcase_app.dart';
import 'package:flutter/material.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await CipherBird.preload();
  runApp(const ShowcaseApp());
}
