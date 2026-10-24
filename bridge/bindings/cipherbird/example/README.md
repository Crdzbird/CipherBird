# CipherBird showcase

One screen per capability, run live on the platform the app is on. Every
row is a check that either holds (green), fails (red) or cannot run on
this platform (grey, with the reason).

| Screen | What it shows |
|---|---|
| Overview | engine version, build kind, the approval boundary for each protected data class, the validated module this platform reports, the profile defaults |
| Primitives | SHA-256, XChaCha20-Poly1305, the hybrid signature, the hybrid KEM, Flagship sealed messaging, a keyring passphrase slot |
| Post-quantum | X-Wing key pairs and seeds, HPKE base mode with DHKEM(X25519), ML-KEM-768 and X-Wing, ML-DSA-65 |
| Envelopes | Suite v2 seal and open, re-addressing rejected, Session v2 handshake and ratchet, an unexpected initiator refused |
| Hardware keys | Secure Enclave or Android Keystore key, wrap and unwrap, a keyring hardware slot, attestation |
| Validated module (WebCrypto in the browser) | DeviceFips through Apple corecrypto or the Android providers: SHA-256, HMAC, HKDF and PBKDF2 against their RFC vectors, AES-256-GCM, P-256 |
| Play | interactive playgrounds, all of them in the browser too since the media ones work on bytes: type your own input, press the buttons, read the log. Hashes and MACs, symmetric encryption with a bit flip, signatures, HPKE with a chosen KEM, Suite v2 with Bob and Carol, a Session v2 chat with Mallory, steganography (a generated photo or sound, or any image, sound or video picked from the device, as the carrier, seven ways to hide a secret including a custom recipe pipeline, wrong-key and damaged-file reveals, inspection and detection), Live entropy (camera frames, through the camera package on phones, the example's own AVFoundation grabber in the macOS Runner and getUserMedia in the browser, or a streamed file feeding a policy-gated source, a meter drawing every chunk and the credit filling towards the seed, then a key drawn from the stream on every credited chunk, or on every reseed or by hand, encrypting and decrypting a message so the ciphertext follows what the camera or the picked file delivers), LavaRand media entropy (any file picked from the device or a generated source, health report with every cutoff, policy-gated harvest, derived keys, DRBG and Fortuna seeding, file-keyed seals and recipes), hardware keys, the validated module |

Run it:

```bash
flutter run -d macos
flutter run -d <ios simulator or device id>
flutter run -d <android device id>
flutter run -d chrome
```

The startup self test prints `CIPHERBIRD_SELFTEST: OK` once the primitives
screen holds, which the scripted verifications read.

The same sections run headless as an integration test and fail on any red
row:

```bash
flutter test integration_test/showcase_test.dart -d <device id>
```

`integration_test/playground_test.dart` presses every playground button;
`integration_test/stego_playground_test.dart` and
`integration_test/entropy_playground_test.dart` drive the steganography and
LavaRand playgrounds through every mode and check what they log;
`integration_test/live_playground_test.dart` streams a photo through the
live source, then the camera where one exists (on macOS a process started
from a shell inherits the launcher's camera permission, so the camera is
exercised only when the app is opened on its own);
`integration_test/hardware_test.dart` and `integration_test/fips_test.dart`
are the focused device tests behind the hardware and module screens.
