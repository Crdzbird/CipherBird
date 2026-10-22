import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/play_choice.dart';

/// The custom encryption pipeline the file playgrounds can apply: profile,
/// layers, error correction and signature are each the developer's pick.
final class RecipeOptions {
  RecipeOptions(this._lib);

  final CipherBird _lib;
  final profile = PlayChoice('Recipe profile', ['balanced', 'high', 'maximum']);
  final layers = PlayChoice('Recipe layers', [
    'profile default',
    'XChaCha20-Poly1305',
    'AES-256-GCM',
    'key-committing AEAD',
    'molecular vault',
    'all four cascaded',
  ]);
  final fec = PlayChoice('Recipe error correction', [
    'none',
    'repetition x3',
    'repetition x5',
    'Hamming(7,4)',
  ]);
  final signature = PlayChoice('Recipe signature', [
    'none',
    'Ed25519',
    'hybrid Ed25519 + ML-DSA',
  ]);
  late final KeyPairResult _ed25519 = _lib.ed25519Keygen();
  late final KeyPairResult _hybrid = _lib.hybridSigKeygen();

  List<PlayChoice> get choices => [profile, layers, fec, signature];

  SecurityProfile get _profile => switch (profile.value) {
    'high' => SecurityProfile.high,
    'maximum' => SecurityProfile.maximum,
    _ => SecurityProfile.balanced,
  };

  FecScheme get _fec => switch (fec.value) {
    'repetition x3' => FecScheme.repetition3,
    'repetition x5' => FecScheme.repetition5,
    'Hamming(7,4)' => FecScheme.hamming74,
    _ => FecScheme.none,
  };

  List<ProtectionLayer>? get _layers => switch (layers.value) {
    'XChaCha20-Poly1305' => const [XChaCha20Layer()],
    'AES-256-GCM' => const [Aes256GcmLayer()],
    'key-committing AEAD' => const [CommittingLayer()],
    'molecular vault' => const [MolecularLayer()],
    'all four cascaded' => const [
      XChaCha20Layer(),
      Aes256GcmLayer(),
      CommittingLayer(),
      MolecularLayer(),
    ],
    _ => null,
  };

  /// A fresh recipe from the current picks around [source].
  CipherBirdRecipe build(KeySource source) {
    final r = _lib.recipe(_profile).withKeySource(source).withFec(_fec);
    final custom = _layers;
    if (custom != null) {
      r.withLayers(custom);
    }
    if (signature.picked('Ed25519')) {
      r.signedBy(_ed25519.secretKey).verifiedBy(_ed25519.publicKey);
    }
    if (signature.picked('hybrid Ed25519 + ML-DSA')) {
      r
          .signedBy(_hybrid.secretKey, algorithm: SignatureAlgorithm.hybrid)
          .verifiedBy(_hybrid.publicKey);
    }
    return r;
  }
}
