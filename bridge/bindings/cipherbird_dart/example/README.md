# cipherbird_dart example

`cipherbird_dart_example.dart` exercises the easy-mode classes and a
maximum-profile recipe from a plain Dart program: a symmetric key with text
round-trips, a post-quantum hybrid signature, one-call public-key encryption
with the hybrid KEM, Argon2id password hashing, and a sealed recipe envelope.

```bash
dart run example/cipherbird_dart_example.dart
```

The bundled engine is found automatically; nothing has to be built or
configured first.
