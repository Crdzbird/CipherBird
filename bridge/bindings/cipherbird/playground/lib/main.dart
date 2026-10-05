import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_playground/src/playground_app.dart';
import 'package:flutter/material.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await CryptoLib.preload();
  runApp(const PlaygroundApp());
}
