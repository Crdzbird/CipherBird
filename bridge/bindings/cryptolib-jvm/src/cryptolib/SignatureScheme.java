package cryptolib;

/**
 * How a {@link Recipe} signs and verifies the plaintext.
 *
 * <p>Implement it for another algorithm; a scheme holding only a public key
 * should throw from {@link #sign}. The signature is applied before encryption,
 * so it stays confidential. Ids 0–127 are reserved; custom schemes must use
 * 128–255, and are verified only through {@link Recipe#verifiedWith}.
 */
public interface SignatureScheme {
    /** Identifier recorded in the envelope header. Built-ins use 1–2; custom 128–255. */
    int id();

    /** Human-readable name, used by {@link Recipe#describe}. */
    String label();

    byte[] sign(CryptoLib lib, byte[] message);

    boolean verify(CryptoLib lib, byte[] message, byte[] signature);
}
