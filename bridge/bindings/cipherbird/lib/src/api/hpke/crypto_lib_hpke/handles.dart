part of '../../../cryptolib.dart';

/// HPKE (RFC 9180) methods on CryptoLib.
extension CryptoLibHpkeHandles on CryptoLib {
  void _hpkeFree(Pointer<Void> h) =>
      _lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('cryptolib_hpke_context_free')(h);
}
