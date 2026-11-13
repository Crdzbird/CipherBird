part of 'web_platform.dart';

/// The marker dart:ffi puts on objects that own native resources, so the
/// classes that carry it compile unchanged on the web.
abstract interface class Finalizable {}
