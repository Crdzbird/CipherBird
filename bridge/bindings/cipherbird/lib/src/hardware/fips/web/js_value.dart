import 'dart:js_interop';

/// A JavaScript value placed in an algorithm dictionary as is, such as a
/// key object for ECDH.
final class JsValue {
  const JsValue(this.value);

  final JSAny value;
}
