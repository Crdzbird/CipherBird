part of '../cipher_bird.dart';

/// What a deployment asks the library to protect, from least to most
/// sensitive. The web build is approved for [ephemeral] only.
enum ProtectedDataClass {
  /// Session keys and transient payloads that live for one exchange.
  ephemeral,

  /// Keys that outlive a session: keyrings, identity keys, stored vaults.
  longLivedKeys,

  /// Cardholder and account data under PCI DSS or an equivalent regime.
  cardData,
}
