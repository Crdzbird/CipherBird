part of '../../cryptolib_ffi.dart';

/// A composable protection pipeline.
///
/// Describe what you want once, then [seal] and [open] with the same recipe.
/// The envelope carries its own descriptor, so opening does not depend on
/// remembering which layers were used - only on holding the key.
///
/// ```dart
/// final recipe = lib.recipe(SecurityProfile.maximum)
///     .withPassphrase('correct horse battery staple')
///     .signedBy(id.secretKey, algorithm: SignatureAlgorithm.hybrid)
///     .verifiedBy(id.publicKey);
///
/// final envelope = recipe.seal(secret);
/// final back = recipe.open(envelope);
/// ```
///
/// Every part is replaceable with your own subclass - see [ProtectionLayer],
/// [KeySource] and [SignatureScheme]. Builder methods return the same
/// instance, so calls chain.
final class CryptoRecipe {
  CryptoRecipe._(this._lib, this.profile) : _layers = List.of(profile.cascade);

  static const List<int> _magic = [0x43, 0x4c, 0x52, 0x43];

  static const List<int> _fecMagic = [0x43, 0x4c, 0x46, 0x43];

  static const int _version = 1;

  static const int _saltLen = 16;

  final CryptoLib _lib;

  /// The profile this recipe started from.
  final SecurityProfile profile;

  List<ProtectionLayer> _layers;

  KeySource? _source;

  SignatureScheme? _signer;

  SignatureScheme? _verifier;

  Uint8List? _verifierKey;

  int? _argon2Ops;

  int? _argon2Memory;

  static Uint8List _prefixLengthed(Uint8List prefix, Uint8List rest) {
    final len = ByteData(4)..setUint32(0, prefix.length);
    return (BytesBuilder()
          ..add(len.buffer.asUint8List())
          ..add(prefix)
          ..add(rest))
        .toBytes();
  }

  static (Uint8List, Uint8List) _splitLengthed(Uint8List data) {
    if (data.length < 4) {
      throw Exception('cryptolib: malformed signed payload');
    }
    final n = ByteData.sublistView(data, 0, 4).getUint32(0);
    if (data.length < 4 + n) {
      throw Exception('cryptolib: malformed signed payload');
    }
    return (
      Uint8List.fromList(data.sublist(4, 4 + n)),
      Uint8List.fromList(data.sublist(4 + n)),
    );
  }

  FecScheme _fec = FecScheme.none;

  /// Use any [KeySource] - a built-in or your own subclass.
  CryptoRecipe withKeySource(KeySource source) {
    _requireValidId(source, source.id, 'key source');
    _source = source;
    return this;
  }

  /// Derive the root key from a passphrase with Argon2id, at this profile's
  /// cost (override with [argon2Cost]). Shorthand for a [PassphraseKeySource].
  CryptoRecipe withPassphrase(String passphrase) =>
      withKeySource(PassphraseKeySource(passphrase));

  /// Use a 32-byte key directly. Shorthand for a [RawKeySource].
  CryptoRecipe withKey(Uint8List key) => withKeySource(RawKeySource(key));

  /// Derive the root key deterministically from a media file. Shorthand for a
  /// [KeyFileSource]. Check the file first with `lib.entropy.assessFileHealth`.
  CryptoRecipe withKeyFile(String path) => withKeySource(KeyFileSource(path));
}
