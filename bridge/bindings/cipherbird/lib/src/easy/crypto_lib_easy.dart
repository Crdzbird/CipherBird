part of '../cipher_bird.dart';

/// `lib.easy` - the easy-mode entry points.
extension CipherBirdEasy on CipherBird {
  /// Keys and helpers with the safe defaults built in.
  EasyApi get easy => EasyApi(this);
}
