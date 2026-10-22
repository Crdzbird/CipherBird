part of '../../cipher_bird.dart';

/// FIPS profile control on CipherBird. Everything in the fips* family runs
/// inside the OpenSSL FIPS Provider (CMVP #4985) when the native library was
/// built with CRYPTOLIB_PROFILE=fips; otherwise [fipsAvailable] is false and
/// every call throws.
extension CipherBirdFips on CipherBird {
  /// Whether the loaded native library is the fips profile.
  bool get fipsAvailable =>
      _lib.lookupFunction<Int32 Function(), int Function()>(
        'cryptolib_fips_available',
      )() ==
      1;

  /// Load the validated module from [moduleDir] with the OpenSSL config at
  /// [configFile], run its self tests and enter approved mode. Null falls
  /// back to CRYPTOLIB_FIPS_MODULE_DIR and CRYPTOLIB_FIPS_CONFIG.
  void fipsInit({String? moduleDir, String? configFile}) {
    final pm = moduleDir == null ? nullptr : moduleDir.toNativeUtf8();
    final pc = configFile == null ? nullptr : configFile.toNativeUtf8();
    try {
      _checkResult(
        _lib.lookupFunction<
          CipherBirdResult Function(Pointer<Utf8>, Pointer<Utf8>),
          CipherBirdResult Function(Pointer<Utf8>, Pointer<Utf8>)
        >('cryptolib_fips_init')(pm, pc),
      );
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pc != nullptr) calloc.free(pc);
    }
  }

  /// The provider state in this process.
  FipsStatus fipsStatus() {
    final s = _lib
        .lookupFunction<
          CipherBirdFipsStatus Function(),
          CipherBirdFipsStatus Function()
        >('cryptolib_fips_status')();
    final out = FipsStatus(
      loaded: s.loaded == 1,
      selfTestsPassed: s.selfTestsPassed == 1,
      approvedMode: s.approvedMode == 1,
      providerName: _utf8OrEmpty(s.providerName),
      providerVersion: _utf8OrEmpty(s.providerVersion),
      moduleDirectory: _utf8OrEmpty(s.moduleDirectory),
      configFile: _utf8OrEmpty(s.configFile),
    );
    for (final p in [
      s.providerName,
      s.providerVersion,
      s.moduleDirectory,
      s.configFile,
    ]) {
      if (p != nullptr) _core.strFree(p);
    }
    return out;
  }

  String _utf8OrEmpty(Pointer<Utf8> p) => p == nullptr ? '' : p.toDartString();
}
