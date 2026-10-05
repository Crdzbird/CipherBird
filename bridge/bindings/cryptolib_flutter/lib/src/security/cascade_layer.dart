part of '../cryptolib.dart';

/// A layer that is itself a mixture of layers - the way to compose several
/// encryptions into one custom class:
///
/// ```dart
/// class BeltAndBraces extends CascadeLayer {
///   const BeltAndBraces() : super(id: 200, wireName: 'belt-and-braces',
///       layers: [XChaCha20Layer(), Aes256GcmLayer(), MyHsmLayer()]);
/// }
/// ```
///
/// Each inner layer receives its own sub-key, HKDF-derived from this layer's
/// key under the inner index and wireName, so nesting never collapses two
/// ciphers onto one key. The AAD is bound by every inner layer. Cascades nest.
class CascadeLayer extends ProtectionLayer {
  const CascadeLayer({
    required this.id,
    required this.wireName,
    required this.layers,
  });

  @override
  final int id;
  @override
  final String wireName;

  /// Inner layers, innermost first.
  final List<ProtectionLayer> layers;

  Uint8List _subKey(CryptoLib lib, Uint8List key, int i) => lib.hkdfDerive(
    key,
    info: Uint8List.fromList('$wireName/$i/${layers[i].wireName}'.codeUnits),
  );

  @override
  Uint8List seal(
    CryptoLib lib,
    Uint8List key,
    Uint8List aad,
    Uint8List plaintext,
  ) {
    if (layers.isEmpty) {
      throw StateError('cryptolib: CascadeLayer "$wireName" has no layers');
    }
    var body = plaintext;
    for (var i = 0; i < layers.length; i++) {
      body = layers[i].seal(lib, _subKey(lib, key, i), aad, body);
    }
    return body;
  }

  @override
  Uint8List open(
    CryptoLib lib,
    Uint8List key,
    Uint8List aad,
    Uint8List ciphertext,
  ) {
    if (layers.isEmpty) {
      throw StateError('cryptolib: CascadeLayer "$wireName" has no layers');
    }
    var body = ciphertext;
    for (var i = layers.length - 1; i >= 0; i--) {
      body = layers[i].open(lib, _subKey(lib, key, i), aad, body);
    }
    return body;
  }
}
