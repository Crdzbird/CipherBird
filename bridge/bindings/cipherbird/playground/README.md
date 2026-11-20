# cipherbird_playground

A one-page Flutter app that uses `cipherbird` the way an application from
pub.dev would: through the easy-mode classes, with no build step for the
native engine. It depends on the plugin by path (`path: ../`).

On start it runs a short self test and lists each check as pass or fail: the
engine version, a SHA-256 known answer, Fortress sealed messaging and a Noise
XX handshake with transport messages. Below that, type a text and press the
buttons:

- encrypt and decrypt with a symmetric key, with a button that flips one bit
  of the ciphertext so the decryption fails
- sign and verify with the hybrid post-quantum signature
- encrypt to your own public key with the hybrid KEM (X25519 + ML-KEM-768) and
  open it with the secret key
- hash a passphrase with Argon2id on a worker

Run it:

```bash
flutter run -d macos
flutter run -d <ios simulator or device id>
flutter run -d <android device id>
```

The larger app, with one screen per capability and the interactive
steganography and entropy playgrounds, is the plugin's
[showcase](../example/README.md).
