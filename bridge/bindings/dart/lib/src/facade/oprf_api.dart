part of '../../cryptolib_ffi.dart';

/// Oblivious pseudorandom function (RFC 9497).
extension type OprfApi(CryptoLib _l) {
  /// Derive an OPRF key pair from a seed (+ optional info). Throws on failure.
  KeyPairResult deriveKeyPair(Uint8List seed, {Uint8List? info}) =>
      _l.oprfDeriveKeyPair(seed, info: info);

  /// Client: blind an input with a fresh random scalar.
  OprfBlindResult blind(Uint8List input) => _l.oprfBlind(input);

  /// Deterministic blind with a caller-supplied scalar (test vectors).
  OprfBlindResult blindWithScalar(Uint8List input, Uint8List blind) =>
      _l.oprfBlindWithScalar(input, blind);

  /// Server: evaluate a blinded element under the secret key.
  Uint8List blindEvaluate(Uint8List secretKey, Uint8List blindedElement) =>
      _l.oprfBlindEvaluate(secretKey, blindedElement);

  /// Client: unblind the evaluated element -> 64-byte PRF output.
  Uint8List finalize(
          Uint8List input, Uint8List blind, Uint8List evaluatedElement) =>
      _l.oprfFinalize(input, blind, evaluatedElement);

  /// Server one-shot: compute the PRF output directly from the key + input.
  Uint8List evaluate(Uint8List secretKey, Uint8List input) =>
      _l.oprfEvaluate(secretKey, input);
}
