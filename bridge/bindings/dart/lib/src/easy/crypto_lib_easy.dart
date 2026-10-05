part of '../../cryptolib_ffi.dart';

/// `lib.easy` - the easy-mode entry points.
extension CryptoLibEasy on CryptoLib {
  /// Keys and helpers with the safe defaults built in.
  EasyApi get easy => EasyApi(this);
}
