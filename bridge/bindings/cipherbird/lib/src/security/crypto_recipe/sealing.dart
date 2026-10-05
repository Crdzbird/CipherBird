part of '../../cryptolib.dart';

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
extension CryptoRecipeSealing on CryptoRecipe {
  /// Apply forward error correction to the finished envelope, so it survives a
  /// carrier that may be recompressed or resampled.
  CryptoRecipe withFec(FecScheme scheme) {
    _fec = scheme;
    return this;
  }

  /// Protect [plaintext] and return the envelope.
  Uint8List seal(Uint8List plaintext) {
    final source =
        _source ??
        (throw StateError(
          'cryptolib: no key set - call withKey/withPassphrase/withKeyFile/withKeySource',
        ));
    final salt = _lib.randomBytes(CryptoRecipe._saltLen);
    final ops = _argon2Ops ?? profile.argon2Ops;
    final mem = _argon2Memory ?? profile.argon2Memory;
    final header = _buildHeader(source, salt, ops, mem);
    final root = _rootKey(source, salt, ops, mem);

    var body = plaintext;
    final signer = _signer;
    if (signer != null) {
      body = CryptoRecipe._prefixLengthed(
        signer.sign(_lib, plaintext),
        plaintext,
      );
    }

    for (var i = 0; i < _layers.length; i++) {
      body = _applyLayer(_layers[i], i, root, salt, header, body, seal: true);
    }

    final envelope = Uint8List(header.length + body.length)
      ..setAll(0, header)
      ..setAll(header.length, body);
    return _fec == FecScheme.none ? envelope : _wrapFec(envelope);
  }

  /// A human-readable summary of what this recipe will do - handy in logs and
  /// code review, where a silently-weak configuration is the thing to catch.
  String describe() {
    final b = StringBuffer('CryptoRecipe(${profile.name})\n')
      ..writeln('  key      : ${_source?.label ?? '(unset)'}')
      ..writeln('  layers   : ${_layers.map((l) => l.wireName).join(' -> ')}')
      ..writeln('  signature: ${_signer?.label ?? 'none'}')
      ..writeln('  fec      : ${_fec.name}');
    if (_source is PassphraseKeySource) {
      final mem = (_argon2Memory ?? profile.argon2Memory) ~/ (1024 * 1024);
      b.writeln(
        '  argon2id : ops=${_argon2Ops ?? profile.argon2Ops}, mem=${mem}MiB',
      );
    }
    return b.toString();
  }
}
