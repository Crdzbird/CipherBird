part of '../../cryptolib.dart';

/// Client OPRF Blind output: the secret blind + the blinded element to send.
final class OprfBlindResult {
  final Uint8List blind;
  final Uint8List blindedElement;
  OprfBlindResult(this.blind, this.blindedElement);
}
