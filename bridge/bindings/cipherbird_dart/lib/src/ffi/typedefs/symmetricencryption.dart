part of '../../cipher_bird.dart';

typedef _SymKeygenC = CipherBirdBufferResult Function();
typedef _SymKeygenDart = CipherBirdBufferResult Function();
typedef _XChaCha20EncC =
    CipherBirdBufferResult Function(
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Uint8> key,
      Size keyLen,
      Pointer<Uint8> aad,
      Size aadLen,
    );
typedef _XChaCha20EncDart =
    CipherBirdBufferResult Function(
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Uint8> key,
      int keyLen,
      Pointer<Uint8> aad,
      int aadLen,
    );
typedef _XChaCha20DecC =
    CipherBirdBufferResult Function(
      Pointer<Uint8> ct,
      Size ctLen,
      Pointer<Uint8> key,
      Size keyLen,
      Pointer<Uint8> aad,
      Size aadLen,
    );
typedef _XChaCha20DecDart =
    CipherBirdBufferResult Function(
      Pointer<Uint8> ct,
      int ctLen,
      Pointer<Uint8> key,
      int keyLen,
      Pointer<Uint8> aad,
      int aadLen,
    );
typedef _Aes256GcmEncC =
    CipherBirdBufferResult Function(
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Uint8> key,
      Size keyLen,
      Pointer<Uint8> aad,
      Size aadLen,
    );
typedef _Aes256GcmEncDart =
    CipherBirdBufferResult Function(
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Uint8> key,
      int keyLen,
      Pointer<Uint8> aad,
      int aadLen,
    );
typedef _Aes256GcmDecC =
    CipherBirdBufferResult Function(
      Pointer<Uint8> ct,
      Size ctLen,
      Pointer<Uint8> key,
      Size keyLen,
      Pointer<Uint8> aad,
      Size aadLen,
    );
typedef _Aes256GcmDecDart =
    CipherBirdBufferResult Function(
      Pointer<Uint8> ct,
      int ctLen,
      Pointer<Uint8> key,
      int keyLen,
      Pointer<Uint8> aad,
      int aadLen,
    );
typedef _Aes256GcmAvailableC = Int32 Function();
typedef _Aes256GcmAvailableDart = int Function();
