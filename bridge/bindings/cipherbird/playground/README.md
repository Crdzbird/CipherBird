# cipherbird playground

An interactive Flutter app that consumes `cipherbird` the way an app would.
Use it to see the library behave, to try inputs, and to watch what fails
closed.

| Section | What you can do |
|---|---|
| Self-test rows | see the library load, a SHA-256 known answer, Fortress sealed messaging and a Noise XX handshake pass on the device |
| Text | type any text; it feeds every operation below |
| Encrypt, Flip a bit, Decrypt | encrypt with the key-committing AEAD, corrupt one bit of the ciphertext, and watch decryption refuse it |
| Sign, Verify | sign with the Ed25519 plus ML-DSA-65 hybrid; change the text afterwards and Verify reports the mismatch |
| Encrypt to my public key | a one-call hybrid X25519 plus ML-KEM-768 envelope, opened again with the app's own secret key |
| Passphrase | hash it with Argon2id on a worker isolate and verify the result |

Every result is shown as selectable text, so ciphertexts, signatures and
PHC strings can be copied out and inspected.

## Run

```bash
flutter run
```

The app depends on the package by path (`cipherbird: path: ../`), so it
always exercises the checked-out source and the committed native binaries.

## Structure

The app follows the package rules: one class per file under 100 lines, no
`else`, no inline comments.

| File | Holds |
|---|---|
| `lib/main.dart` | the startup sequence with the awaited `CryptoLib.preload()` |
| `lib/src/playground_app.dart` | the `MaterialApp` |
| `lib/src/playground_page.dart` | the page widget and the `part` directives |
| `lib/src/playground_page_state.dart` | the keys, the text controllers and the layout |
| `lib/src/playground_actions.dart` | one method per button |
| `lib/src/self_test.dart` | the self-test rows and the Noise round trip |
| `lib/src/result_block.dart` | the titled, selectable result widget |
