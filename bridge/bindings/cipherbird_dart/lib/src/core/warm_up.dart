part of '../cipher_bird.dart';

Future<bool> _warmUp(CipherBirdRunner runner) async {
  try {
    return await runner.runHeavy(_warmInWorker);
  } on Object catch (_) {
    return false;
  }
}

bool _warmInWorker() {
  final warm = CipherBird.load()..init();
  warm.version();
  return true;
}
