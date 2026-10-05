part of '../cipher_bird.dart';

Future<bool> _warmUp(CipherBirdRunner runner, String? library) async {
  try {
    return await runner.runHeavy(() => _warmInWorker(library));
  } on Object catch (_) {
    return false;
  }
}

bool _warmInWorker(String? library) {
  final warm = CipherBird.load(library)..init();
  warm.version();
  return true;
}
