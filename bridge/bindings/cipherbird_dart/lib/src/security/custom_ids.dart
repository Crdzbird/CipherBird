part of '../cipher_bird.dart';

const int _customIdMin = 128;

const int _customIdMax = 255;

void _requireValidId(Object part, int id, String what) {
  if (part is _Builtin) {
    return;
  }
  if (id < _customIdMin || id > _customIdMax) {
    throw ArgumentError.value(
      id,
      'id',
      'custom $what ids must be in $_customIdMin..$_customIdMax (0–127 are reserved)',
    );
  }
}
