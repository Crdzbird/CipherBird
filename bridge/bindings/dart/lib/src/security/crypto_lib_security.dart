part of '../../cryptolib_ffi.dart';

/// Profile-driven entry points.
extension CryptoLibSecurity on CryptoLib {
  /// Start a [CryptoRecipe] at the given profile's settings.
  ///
  /// The profile only sets defaults - every part stays overridable.
  CryptoRecipe recipe([SecurityProfile profile = SecurityProfile.balanced]) =>
      CryptoRecipe._(this, profile);

  /// A recipe using the strongest option at every choice. Shorthand for
  /// `recipe(SecurityProfile.maximum)`.
  CryptoRecipe maximumSecurity() =>
      CryptoRecipe._(this, SecurityProfile.maximum);
}
