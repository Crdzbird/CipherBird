package cryptolib;

/**
 * Where a {@link Recipe}'s 32-byte root key comes from.
 *
 * <p>Implement it for a hardware token, a KMS, a keyring unlock — anything that
 * can produce the same 32 bytes again when opening. The recipe refuses any
 * other length. Ids 0–127 are reserved; custom sources must use 128–255.
 */
public interface KeySource {
    /** Identifier recorded in the envelope header. Built-ins use 0–2; custom 128–255. */
    int id();

    /** Human-readable name, used by {@link Recipe#describe}. */
    String label();

    /**
     * Produce the root key.
     *
     * @param salt         fresh per envelope
     * @param argon2Ops    the recipe's Argon2id cost, for sources that stretch a weak input
     * @param argon2Memory the recipe's Argon2id memory in bytes
     */
    byte[] deriveRoot(CryptoLib lib, byte[] salt, long argon2Ops, long argon2Memory);
}
