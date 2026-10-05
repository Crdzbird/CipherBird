part of '../cryptolib.dart';

Future<bool> _warmUp(CryptoLibRunner runner) async {
  try {
    return await runner.runHeavy(_warmInWorker);
  } on Object catch (_) {
    return false;
  }
}

bool _warmInWorker() {
  final warm = CryptoLib.load()..init();
  warm.version();
  return true;
}
