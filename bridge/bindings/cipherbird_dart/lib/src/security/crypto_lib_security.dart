part of '../cipher_bird.dart';

/// Profile-driven entry points.
extension CipherBirdSecurity on CipherBird {
  /// Start a [CipherBirdRecipe] at the given profile's settings.
  ///
  /// The profile only sets defaults - every part stays overridable.
  CipherBirdRecipe recipe([
    SecurityProfile profile = SecurityProfile.balanced,
  ]) => CipherBirdRecipe._(this, profile);

  /// A recipe using the strongest option at every choice. Shorthand for
  /// `recipe(SecurityProfile.maximum)`.
  CipherBirdRecipe maximumSecurity() =>
      CipherBirdRecipe._(this, SecurityProfile.maximum);
}
