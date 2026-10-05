part of '../../cipher_bird.dart';

/// Sender-side HPKE result: the KEM encapsulation plus the sender context.
final class HpkeSender {
  final Uint8List enc;
  final HpkeContext context;
  HpkeSender(this.enc, this.context);
}
