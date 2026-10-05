part of '../../cipher_bird.dart';

typedef _SymKeygenC = CryptoBufferResult Function();
typedef _SymKeygenDart = CryptoBufferResult Function();
typedef _XChaCha20EncC =
    CryptoBufferResult Function(
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Uint8> key,
      Size keyLen,
      Pointer<Uint8> aad,
      Size aadLen,
    );
typedef _XChaCha20EncDart =
    CryptoBufferResult Function(
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Uint8> key,
      int keyLen,
      Pointer<Uint8> aad,
      int aadLen,
    );
typedef _XChaCha20DecC =
    CryptoBufferResult Function(
      Pointer<Uint8> ct,
      Size ctLen,
      Pointer<Uint8> key,
      Size keyLen,
      Pointer<Uint8> aad,
      Size aadLen,
    );
typedef _XChaCha20DecDart =
    CryptoBufferResult Function(
      Pointer<Uint8> ct,
      int ctLen,
      Pointer<Uint8> key,
      int keyLen,
      Pointer<Uint8> aad,
      int aadLen,
    );
typedef _Aes256GcmEncC =
    CryptoBufferResult Function(
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Uint8> key,
      Size keyLen,
      Pointer<Uint8> aad,
      Size aadLen,
    );
typedef _Aes256GcmEncDart =
    CryptoBufferResult Function(
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Uint8> key,
      int keyLen,
      Pointer<Uint8> aad,
      int aadLen,
    );
typedef _Aes256GcmDecC =
    CryptoBufferResult Function(
      Pointer<Uint8> ct,
      Size ctLen,
      Pointer<Uint8> key,
      Size keyLen,
      Pointer<Uint8> aad,
      Size aadLen,
    );
typedef _Aes256GcmDecDart =
    CryptoBufferResult Function(
      Pointer<Uint8> ct,
      int ctLen,
      Pointer<Uint8> key,
      int keyLen,
      Pointer<Uint8> aad,
      int aadLen,
    );
typedef _Aes256GcmAvailableC = Int32 Function();
typedef _Aes256GcmAvailableDart = int Function();
