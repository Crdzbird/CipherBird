part of '../../../cipher_bird.dart';

/// HPKE (RFC 9180) methods on CipherBird.
extension CipherBirdHpkeHandles on CipherBird {
  void _hpkeFree(Pointer<Void> h) =>
      _lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('cryptolib_hpke_context_free')(h);
}
