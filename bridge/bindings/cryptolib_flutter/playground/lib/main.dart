import 'package:cryptolib_flutter/cryptolib_flutter.dart';
import 'package:cryptolib_playground/src/playground_app.dart';
import 'package:flutter/material.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await CryptoLib.preload();
  runApp(const PlaygroundApp());
}
